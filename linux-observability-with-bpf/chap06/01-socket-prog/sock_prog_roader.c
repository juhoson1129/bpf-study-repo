#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

// 간단한 raw socket open 함수
int open_raw_sock(const char *name) {
    struct sockaddr_ll sll;
    int sock;

    sock = socket(PF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(ETH_P_ALL));
    if (sock < 0) {
        printf("cannot create raw socket\n");
        return -1;
    }

    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = if_nametoindex(name);
    sll.sll_protocol = htons(ETH_P_ALL);
    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        printf("bind to %s: %s\n", name, strerror(errno));
        close(sock);
        return -1;
    }

    return sock;
}

int main(int argc, char **argv) {
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_map *map;
    int prog_fd, map_fd;
    int sock = -1;
    int i, key;
    int tcp_cnt, udp_cnt, icmp_cnt;
    const char *filename = argv[1];

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <bpf_object_file>\n", argv[0]);
        return 1;
    }

    // 1. BPF 오브젝트 열기
    obj = bpf_object__open_file(filename, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: opening BPF object file failed\n");
        return 1;
    }

    // 2. BPF 로드
    if (bpf_object__load(obj)) {
        fprintf(stderr, "ERROR: loading BPF object file failed\n");
        return 1;
    }

    // 3. 프로그램 및 맵 찾기
    // sock_prog_example.c에서 SEC("socket")으로 정의했으므로 프로그램 이름은 섹션 이름 기반일 수 있음
    // 하지만 보통 첫 번째 프로그램을 가져오면 됨.
    prog = bpf_object__next_program(obj, NULL);
    if (!prog) {
        fprintf(stderr, "ERROR: finding BPF program failed\n");
        return 1;
    }
    prog_fd = bpf_program__fd(prog);

    map = bpf_object__find_map_by_name(obj, "countmap");
    if (!map) {
        fprintf(stderr, "ERROR: finding BPF map failed\n");
        return 1;
    }
    map_fd = bpf_map__fd(map);

    // 4. 소켓 열기 및 BPF 부착
    sock = open_raw_sock("eth0"); // 예제니까 lo 인터페이스 사용, 필요시 eth0 등으로 변경
    if (sock < 0) return 1;

    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd))) {
        fprintf(stderr, "setsockopt error: %s\n", strerror(errno));
        return 1;
    }

    // 5. 맵 조회 루프
    for (i = 0; i < 10; i++) {
        key = IPPROTO_TCP;
        if (bpf_map_lookup_elem(map_fd, &key, &tcp_cnt) != 0) tcp_cnt = 0;

        key = IPPROTO_UDP;
        if (bpf_map_lookup_elem(map_fd, &key, &udp_cnt) != 0) udp_cnt = 0;

        key = IPPROTO_ICMP;
        if (bpf_map_lookup_elem(map_fd, &key, &icmp_cnt) != 0) icmp_cnt = 0;

        printf("TCP %d UDP %d ICMP %d packets\n", tcp_cnt, udp_cnt, icmp_cnt);
        sleep(1);
    }

    return 0;
}