package tracer

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/ismajl-ramadani/kwatch-ebpf/internal/bpf"
	"github.com/ismajl-ramadani/kwatch-ebpf/internal/models"
)

// The raw memory mapping from C
type bpfEvent struct {
	Pid        uint32
	Ppid       uint32
	Uid        uint32
	Gid        uint32
	Type       uint32
	Pad        uint32
	DurationNs uint64
	CgroupId   uint64
	Comm       [16]byte
	Filename   [256]byte
	Args       [512]byte
	DstIP      uint32
	DstPort    uint16
	AF         uint16
}

// Start loads the eBPF program and streams structured JSON events to a channel
func Start(eventChan chan<- models.EventJSON, stopChan <-chan struct{}) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("failed to remove memlock: %v", err)
	}

	objs := bpf.BpfObjects{}
	if err := bpf.LoadBpfObjects(&objs, nil); err != nil {
		return fmt.Errorf("loading objects: %v", err)
	}
	defer objs.Close()

	// Link all your tracepoints
	links := []link.Link{}
	l, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.TraceExecve, nil)
	if err == nil { links = append(links, l) }
	
	l, err = link.Tracepoint("sched", "sched_process_exit", objs.TraceExit, nil)
	if err == nil { links = append(links, l) }
	
	l, err = link.Tracepoint("syscalls", "sys_enter_connect", objs.TraceConnect, nil)
	if err == nil { links = append(links, l) }
	
	l, err = link.Tracepoint("syscalls", "sys_enter_accept", objs.TraceAcceptEnter, nil)
	if err == nil { links = append(links, l) }
	
	l, err = link.Tracepoint("syscalls", "sys_exit_accept", objs.TraceAcceptExit, nil)
	if err == nil { links = append(links, l) }
	
	l, err = link.Tracepoint("syscalls", "sys_enter_openat", objs.TraceOpenat, nil)
	if err == nil { links = append(links, l) }

	defer func() {
		for _, lnk := range links {
			lnk.Close()
		}
	}()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return fmt.Errorf("failed to open ringbuf reader: %v", err)
	}
	defer rd.Close()

	go func() {
		<-stopChan
		rd.Close()
	}()

	log.Println("eBPF Tracer hooked into kernel. Listening for events...")

	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			continue
		}

		var raw bpfEvent
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &raw); err != nil {
			continue
		}

		comm := string(bytes.TrimRight(raw.Comm[:], "\x00"))
		path := string(bytes.TrimRight(raw.Filename[:], "\x00"))
		ev := models.EventJSON{PID: raw.Pid, PPID: raw.Ppid, UID: raw.Uid, GID: raw.Gid, Command: comm, CgroupID: raw.CgroupId}

		switch raw.Type {
		case 4: // open
			if !models.IsSensitive(path) { continue }
			ev.Type = "open"
			ev.Path = path
		case 2: // connect
			ev.Type = "connect"
			ev.DstAddr = fmt.Sprintf("%d.%d.%d.%d:%d", raw.DstIP>>24, (raw.DstIP>>16)&0xFF, (raw.DstIP>>8)&0xFF, raw.DstIP&0xFF, raw.DstPort)
		case 3: // accept
			ev.Type = "accept"
			ev.DstAddr = fmt.Sprintf("%d.%d.%d.%d:%d", raw.DstIP>>24, (raw.DstIP>>16)&0xFF, (raw.DstIP>>8)&0xFF, raw.DstIP&0xFF, raw.DstPort)
		case 1: // exit
			ev.Type = "exit"
			ev.Duration = models.FmtDuration(raw.DurationNs)
		case 0: // exec
			proc := enrichFromProc(raw.Pid)
			var argParts []string
			for start := 0; start < len(raw.Args); start += 64 {
				s := strings.TrimRight(string(raw.Args[start:start+64]), "\x00")
				if s == "" { break }
				argParts = append(argParts, s)
			}
			ev.Type = "exec"
			ev.Path = path
			ev.Exe = proc.exe
			ev.CWD = proc.cwd
			ev.MemoryKB = proc.memoryKB
			ev.FDCount = proc.fdCount
			ev.Args = strings.Join(argParts, " ")
		}

		select {
		case eventChan <- ev:
		default: // drop if channel full
		}
	}
}