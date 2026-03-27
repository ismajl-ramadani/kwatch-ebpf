# kwatch-ebpf

> An experimentation project — built to experiment/learn eBPF, not for production use.

eBPF-based kernel process monitor. Hooks into kernel tracepoints to capture process execution, network connections, and sensitive file access.

## What it traces

| Event | Hook |
|---|---|
| Process exec + argv | `tracepoint/syscalls/sys_enter_execve` |
| Process exit + lifetime | `tracepoint/sched/sched_process_exit` |
| Outbound connections (IPv4) | `tracepoint/syscalls/sys_enter_connect` |
| Inbound connections (IPv4) | `tracepoint/syscalls/sys_enter_accept{4}` |
| Sensitive file access | `tracepoint/syscalls/sys_enter_openat` |

Process events are enriched from `/proc/[pid]/` (exe, cwd, ppid, memory, fd count) immediately after the kernel event arrives.

## Stack

- **Kernel:** C + eBPF, compiled via [cilium/ebpf](https://github.com/cilium/ebpf) / bpf2go
- **Backend:** Go

## Run

```bash
# generate ebpf bytecode
go generate ./internal/bpf/

# build
go build -o kwatch ./cmd/kwatch/

# run (requires root for eBPF)
sudo ./kwatch start

```

## Test
```bash
sudo go test -tags=integration ./internal/tracer/ -v
```

Requires Linux 5.8+ with BTF enabled (`CONFIG_DEBUG_INFO_BTF=y`).

## References

- [eBPF — what is it?](https://ebpf.io/what-is-ebpf/)
- [cilium/ebpf Go library](https://github.com/cilium/ebpf)
- [Linux tracepoints](https://www.kernel.org/doc/html/latest/trace/tracepoints.html)
- [BPF ring buffer](https://www.kernel.org/doc/html/latest/bpf/ringbuf.html)
- [Falco](https://falco.org) and [Tetragon](https://tetragon.io) — production tools built on similar ideas
