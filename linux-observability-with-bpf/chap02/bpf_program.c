// vmlinux.h는 bpftool을 사용하여 생성해야 합니다.
// bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

SEC("tracepoint/syscalls/sys_enter_execve")
int bpf_prog(struct trace_event_raw_sys_enter *ctx) {
	// bpf_printk는 BPF 프로그램에서 디버깅 메시지를 출력하는 헬퍼 함수입니다.
	// /sys/kernel/debug/tracing/trace_pipe 파일에서 출력을 확인할 수 있습니다.
	bpf_printk("Hello, BPF World!");
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
