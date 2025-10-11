#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <bpf/libbpf.h>


// 프로그램 종료를 위한 플래그
static volatile bool stop = false;

// Ctrl+C 시그널을 처리하여 프로그램을 안전하게 종료합니다.
static void sig_handler(int sig)
{
	stop = true;
}

int main(int argc, char **argv)
{
	struct bpf_object *obj;
	struct bpf_program *prog;
	int err;
	const char *bpf_file = "bpf_program.o";

	// libbpf의 기본 로깅 콜백을 설정하여 더 자세한 오류 메시지를 볼 수 있게 합니다.
	libbpf_set_print(NULL);

	// SIGINT, SIGTERM 시그널 핸들러 설정
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	// 1. BPF 오브젝트 파일 열기
	obj = bpf_object__open_file(bpf_file, NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: BPF 오브젝트 파일 열기 실패: %s\n", bpf_file);
		return 1;
	}

	// 2. BPF 프로그램 커널에 로드하기
	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "ERROR: BPF 오브젝트 로드 실패: %d\n", err);
		bpf_object__close(obj);
		return 1;
	}

	// 3. BPF 프로그램 연결(attach)하기
	// 오브젝트 내의 각 프로그램을 순회하며 attach 합니다.
	bpf_object__for_each_program(prog, obj) {
		struct bpf_link *link = bpf_program__attach(prog);
		if (libbpf_get_error(link)) {
			const char *prog_name = bpf_program__name(prog);
			fprintf(stderr, "ERROR: '%s' 프로그램 연결 실패\n", prog_name);
			bpf_object__close(obj);
			return 1;
		}
		// libbpf는 bpf_object__close 시점에 자동으로 link를 정리합니다.
	}	

	printf("BPF 프로그램이 성공적으로 로드 및 연결되었습니다. 'execve' 시스템 콜을 감시합니다...\n");
	printf("다른 터미널에서 'sudo cat /sys/kernel/debug/tracing/trace_pipe' 명령으로 출력을 확인하세요.\n");
	printf("프로그램을 종료하려면 Ctrl+C를 누르세요.\n");

	while (!stop) {
		sleep(1);
	}

	printf("\n프로그램을 종료합니다.\n");
	bpf_object__close(obj);

	return 0;
}