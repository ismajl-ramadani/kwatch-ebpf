// go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
    __u32 pid;
    __u8 comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16mb buffer
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(void *ctx) {
    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0; // failed to reserve space, drop the event
    }

    e->pid = bpf_get_current_pid_tgid() >> 32;

    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // submit event to user space
    bpf_ringbuf_submit(e, 0);

    return 0;
}