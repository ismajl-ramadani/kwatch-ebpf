package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf _kwatch.c

type bpfEvent struct {
	Pid        uint32
	Uid        uint32
	Gid        uint32
	Type       uint32     // 0=exec, 1=exit, 2=connect, 3=accept
	DurationNs uint64     // nanoseconds alive (exit events only)
	Comm       [16]byte
	Filename   [256]byte
	Args       [512]byte  // argv[1..8], fixed 64-byte slots (exec only)
	DstIP      uint32     // IPv4 host byte order (connect/accept)
	DstPort    uint16
	AF         uint16
}

type EventJSON struct {
	Type     string `json:"type"`     // "exec" | "exit"
	PID      uint32 `json:"pid"`
	PPID     int    `json:"ppid"`
	UID      uint32 `json:"uid"`
	GID      uint32 `json:"gid"`
	Command  string `json:"command"`
	Path     string `json:"path"`
	Exe      string `json:"exe"`
	CWD      string `json:"cwd"`
	MemoryKB int    `json:"memory_kb"`
	FDCount  int    `json:"fd_count"`
	Duration string `json:"duration,omitempty"` // human-readable lifetime, exit only
	DstAddr  string `json:"dst_addr,omitempty"` // "1.2.3.4:443", connect/accept only
	Args     string `json:"args,omitempty"`     // space-joined argv[1..], exec only
}

// Specific files that are always interesting regardless of who opens them.
var sensitiveFiles = []string{
	"/etc/passwd", "/etc/shadow", "/etc/gshadow",
	"/etc/sudoers", "/etc/crontab",
}

// Path substrings — match anywhere in the path (catches nested .ssh dirs, etc.)
var sensitiveSubstrings = []string{
	"/.ssh/", "/id_rsa", "/id_ed25519", "/.gnupg/",
	"/proc/1/mem", "/proc/1/maps",
	"/run/secrets", "/var/run/secrets", // k8s secrets mounts
}

// Prefix matches for broad areas.
var sensitivePrefixes = []string{
	"/root/", "/etc/sudoers.d/", "/etc/cron.d/",
}

func isSensitive(path string) bool {
	for _, f := range sensitiveFiles {
		if path == f {
			return true
		}
	}
	for _, sub := range sensitiveSubstrings {
		if strings.Contains(path, sub) {
			return true
		}
	}
	for _, prefix := range sensitivePrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// fmtDuration converts nanoseconds to a human-readable lifetime string.
func fmtDuration(ns uint64) string {
	switch {
	case ns < 1_000:
		return fmt.Sprintf("%dns", ns)
	case ns < 1_000_000:
		return fmt.Sprintf("%.2fµs", float64(ns)/1e3)
	case ns < 1_000_000_000:
		return fmt.Sprintf("%.2fms", float64(ns)/1e6)
	case ns < 60_000_000_000:
		return fmt.Sprintf("%.3fs", float64(ns)/1e9)
	default:
		secs := ns / 1_000_000_000
		return fmt.Sprintf("%dh %dm %ds", secs/3600, (secs%3600)/60, secs%60)
	}
}

// procInfo holds data collected from /proc/[pid]/
type procInfo struct {
	ppid     int
	exe      string
	cwd      string
	memoryKB int
	fdCount  int
}

// enrichFromProc reads /proc/[pid]/ immediately after the kernel event arrives.
// The process may be short-lived, so we do this as fast as possible.
func enrichFromProc(pid uint32) procInfo {
	base := fmt.Sprintf("/proc/%d", pid)
	info := procInfo{}

	// /proc/[pid]/exe — the resolved real path of the executable
	if exe, err := os.Readlink(filepath.Join(base, "exe")); err == nil {
		info.exe = exe
	}

	// /proc/[pid]/cwd — the current working directory
	if cwd, err := os.Readlink(filepath.Join(base, "cwd")); err == nil {
		info.cwd = cwd
	}

	// /proc/[pid]/status — ppid and memory usage
	if f, err := os.Open(filepath.Join(base, "status")); err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "PPid:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					info.ppid, _ = strconv.Atoi(fields[1])
				}
			}
			if strings.HasPrefix(line, "VmRSS:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					info.memoryKB, _ = strconv.Atoi(fields[1])
				}
			}
		}
	}

	// /proc/[pid]/fd — count of open file descriptors
	if entries, err := os.ReadDir(filepath.Join(base, "fd")); err == nil {
		info.fdCount = len(entries)
	}

	return info
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("failed to remove memlock: %v", err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TraceExecve, nil)
	if err != nil {
		log.Fatalf("linking tracepoint: %v", err)
	}
	defer tp.Close()

	exitTp, err := link.Tracepoint("sched", "sched_process_exit", objs.TraceExit, nil)
	if err != nil {
		log.Fatalf("linking exit tracepoint: %v", err)
	}
	defer exitTp.Close()

	connTp, err := link.Tracepoint("syscalls", "sys_enter_connect", objs.TraceConnect, nil)
	if err != nil {
		log.Fatalf("linking connect tracepoint: %v", err)
	}
	defer connTp.Close()

	accEnter, err := link.Tracepoint("syscalls", "sys_enter_accept", objs.TraceAcceptEnter, nil)
	if err != nil {
		log.Fatalf("linking accept enter tracepoint: %v", err)
	}
	defer accEnter.Close()

	accExit, err := link.Tracepoint("syscalls", "sys_exit_accept", objs.TraceAcceptExit, nil)
	if err != nil {
		log.Fatalf("linking accept exit tracepoint: %v", err)
	}
	defer accExit.Close()

	acc4Enter, err := link.Tracepoint("syscalls", "sys_enter_accept4", objs.TraceAccept4Enter, nil)
	if err != nil {
		log.Fatalf("linking accept4 enter tracepoint: %v", err)
	}
	defer acc4Enter.Close()

	acc4Exit, err := link.Tracepoint("syscalls", "sys_exit_accept4", objs.TraceAccept4Exit, nil)
	if err != nil {
		log.Fatalf("linking accept4 exit tracepoint: %v", err)
	}
	defer acc4Exit.Close()

	openTp, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.TraceOpenat, nil)
	if err != nil {
		log.Fatalf("linking openat tracepoint: %v", err)
	}
	defer openTp.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("failed to open ringbuf reader: %v", err)
	}
	defer rd.Close()

	eventChan := make(chan EventJSON, 1000)

	http.HandleFunc("/stream", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming unsupported!", http.StatusInternalServerError)
			return
		}

		log.Println("Client connected to /stream")

		for ev := range eventChan {
			data, _ := json.Marshal(ev)
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	})


	go func() {
		log.Println("Starting HTTP SSE stream server on :8080")
		if err := http.ListenAndServe(":8080", nil); err != nil {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	log.Println("kwatch-ebpf is running! Listening for events... (press Ctrl+C to exit)")

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-stopper
		rd.Close()
	}()

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("exiting kwatch-ebpf...")
				return
			}
			log.Printf("reading from ringbuf: %v", err)
			continue
		}

		var raw bpfEvent
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &raw); err != nil {
			log.Printf("failed to parse ringbuf record: %v", err)
			continue
		}

		comm := string(bytes.TrimRight(raw.Comm[:], "\x00"))
		path := string(bytes.TrimRight(raw.Filename[:], "\x00"))

		var ev EventJSON
		if raw.Type == 4 {
			// Open event — log everything, but only push sensitive paths to the frontend.
			log.Printf("OPEN    PID:%-6d UID:%-4d CMD:%-16s PATH:%s",
				raw.Pid, raw.Uid,
				string(bytes.TrimRight(raw.Comm[:], "\x00")), path)
			if !isSensitive(path) {
				continue
			}
			ev = EventJSON{
				Type:    "open",
				PID:     raw.Pid,
				UID:     raw.Uid,
				GID:     raw.Gid,
				Command: comm,
				Path:    path,
			}
		} else if raw.Type == 2 {
			// Connect event — format IPv4 as "a.b.c.d:port"
			ip := raw.DstIP
			dst := fmt.Sprintf("%d.%d.%d.%d:%d",
				ip>>24, (ip>>16)&0xFF, (ip>>8)&0xFF, ip&0xFF,
				raw.DstPort)
			ev = EventJSON{
				Type:    "connect",
				PID:     raw.Pid,
				UID:     raw.Uid,
				GID:     raw.Gid,
				Command: comm,
				DstAddr: dst,
			}
			log.Printf("CONNECT PID:%-6d UID:%-4d CMD:%-16s DST:%s",
				ev.PID, ev.UID, ev.Command, ev.DstAddr)
		} else if raw.Type == 3 {
			// Accept event — dst_ip/dst_port hold the connecting client's address.
			ip := raw.DstIP
			src := fmt.Sprintf("%d.%d.%d.%d:%d",
				ip>>24, (ip>>16)&0xFF, (ip>>8)&0xFF, ip&0xFF,
				raw.DstPort)
			ev = EventJSON{
				Type:    "accept",
				PID:     raw.Pid,
				UID:     raw.Uid,
				GID:     raw.Gid,
				Command: comm,
				DstAddr: src,
			}
			log.Printf("ACCEPT  PID:%-6d UID:%-4d CMD:%-16s FROM:%s",
				ev.PID, ev.UID, ev.Command, ev.DstAddr)
		} else if raw.Type == 1 {
			// Exit event — process may already be gone, skip /proc enrichment.
			dur := fmtDuration(raw.DurationNs)
			ev = EventJSON{
				Type:     "exit",
				PID:      raw.Pid,
				UID:      raw.Uid,
				GID:      raw.Gid,
				Command:  comm,
				Duration: dur,
			}
			log.Printf("EXIT  PID:%-6d UID:%-4d CMD:%-16s LIVED:%s",
				ev.PID, ev.UID, ev.Command, ev.Duration)
		} else {
			// Exec event — enrich synchronously while process is alive.
			proc := enrichFromProc(raw.Pid)

			// Parse space-joined args from fixed 64-byte slots.
			var argParts []string
			for start := 0; start < len(raw.Args); start += 64 {
				s := strings.TrimRight(string(raw.Args[start:start+64]), "\x00")
				if s == "" {
					break
				}
				argParts = append(argParts, s)
			}

			ev = EventJSON{
				Type:     "exec",
				PID:      raw.Pid,
				PPID:     proc.ppid,
				UID:      raw.Uid,
				GID:      raw.Gid,
				Command:  comm,
				Path:     path,
				Exe:      proc.exe,
				CWD:      proc.cwd,
				MemoryKB: proc.memoryKB,
				FDCount:  proc.fdCount,
				Args:     strings.Join(argParts, " "),
			}
			log.Printf("EXEC  PID:%-6d PPID:%-6d UID:%-4d CMD:%-16s PATH:%s ARGS:%s",
				ev.PID, ev.PPID, ev.UID, ev.Command, ev.Path, ev.Args)
		}

		select {
		case eventChan <- ev:
		default:
			log.Println("channel full, dropping event")
		}
	}
}