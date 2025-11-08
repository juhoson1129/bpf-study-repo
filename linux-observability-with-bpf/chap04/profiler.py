from bcc import BPF, PerfSWConfig, PerfType
import sys
import errno
import signal
from time import sleep



# BPF 프로그램 소스 코드
bpf_source = """
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf_perf_event.h>

struct trace_t{
    int stack_id;
};

BPF_HASH(cache, struct trace_t);
BPF_STACK_TRACE(traces, 10000);
"""

bpf_source += """
int collect_stack_traces(struct bpf_perf_event_data *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != PROGRAM_PID)
        return 0;

    struct trace_t trace = {
        .stack_id = traces.get_stackid(&ctx->regs, BPF_F_USER_STACK)
    };

    cache.increment(trace);
    return 0;
}
"""

if len(sys.argv) < 2:
    print("사용법: sudo python3 profiler.py <pid> [출력_파일_경로]")
    sys.exit(1)

program_pid = int(sys.argv[1])
output_file = sys.argv[2] if len(sys.argv) > 2 else None
bpf_source = bpf_source.replace("PROGRAM_PID", str(program_pid))
bpf = BPF(text=bpf_source)
bpf.attach_perf_event(ev_type = PerfType.SOFTWARE,
                      ev_config = PerfSWConfig.CPU_CLOCK, # CPU 클럭 이벤트를 사용
                      fn_name = "collect_stack_traces",
                      sample_freq=99) # 초당 99회 샘플링하도록 설정

try:
    print(f"Profiling PID {program_pid} at 99Hz... Press Ctrl+C to stop.")
    sleep(99999999)
except KeyboardInterrupt:
    # KeyboardInterrupt가 발생한 후 추가적인 SIGINT 신호를 무시합니다.
    signal.signal(signal.SIGINT, signal.SIG_IGN)

print("\n결과를 처리 중입니다...")

output_lines = []
for trace, acc in sorted(bpf["cache"].items(), key=lambda cache: cache[1].value):
    line = []
    if trace.stack_id < 0 and trace.stack_id == -errno.EFAULT:
        line = [b'Unknown stack']
    else:
        stack_trace = list(bpf["traces"].walk(trace.stack_id))
        for stack_address in reversed(stack_trace):
            line.append(bpf.sym(stack_address, program_pid))
    frame = b";".join(line).decode('utf-8', 'replace')
    output_lines.append("%s %d" % (frame, acc.value))

if output_file:
    print(f"결과를 '{output_file}' 파일에 저장합니다.")
    with open(output_file, "w") as f:
        f.write("\n".join(output_lines))
else:
    for line in output_lines:
        print(line)