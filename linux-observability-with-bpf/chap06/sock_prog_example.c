// vmlinux.h는 bpftool을 사용하여 생성해야 합니다.
// bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define ETH_HLEN 14

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 256);
	__type(key, int);
	__type(value, int);
} countmap SEC(".maps");

SEC("socket")
int socket_prog(struct __sk_buff *skb) {
	// load_byte는 legacy BPF instruction(LD_ABS)을 사용하므로 bpf_skb_load_bytes로 대체합니다.
	// offsetof는 컴파일러 내장 기능을 사용합니다.
	int proto_offset = ETH_HLEN + __builtin_offsetof(struct iphdr, protocol);
	unsigned char proto = 0;
	
	// 패킷 데이터에서 프로토콜 바이트를 읽어옵니다.
	if (bpf_skb_load_bytes(skb, proto_offset, &proto, sizeof(proto)) < 0) {
		return 0;
	}

	int key = proto;
	int one = 1;
	int *el = bpf_map_lookup_elem(&countmap, &key);
	
	if (el) {
		(*el)++;
	} else {
		// BPF_MAP_TYPE_ARRAY는 미리 0으로 초기화되므로 lookup 실패는 거의 없지만 안전을 위해 처리
		bpf_map_update_elem(&countmap, &key, &one, BPF_ANY);
	}
	
	return 0;
}

