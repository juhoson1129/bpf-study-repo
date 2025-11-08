from bcc import BPF

# BPF 프로그램 소스 코드
bpf_source = """
#include <linux/sched.h>

// 시스템 콜 진입 시 실행될 함수
int trace_execve_entry(struct pt_regs *ctx) {
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm)); // 현재 프로세스 이름 가져오기
    bpf_trace_printk("executing program: %s\\n", comm); // 추적 메시지 출력
    return 0; 
};
"""

bpf = BPF(text=bpf_source)
bpf.attach_kprobe(event=bpf.get_syscall_fnname("execve"), fn_name="trace_execve_entry")

print("Tracing execve syscalls... Press Ctrl+C to end.")

# Ctrl+C (KeyboardInterrupt) 예외를 처리하여 좀비프로세스 없이 종료.
# 이런 예외처리가 없으면 프로세스가 trace_pipe를 점유한 채로 남아버림.
try:
    # /sys/kernel/debug/tracing/trace_pipe 내용을 출력합니다.
    bpf.trace_print()
except KeyboardInterrupt:
    print("\nDetaching kprobe and exiting.")
