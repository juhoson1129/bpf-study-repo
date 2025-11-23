# Chapter 6: BPF Socket Program Example

이 문서는 `sock_prog_example.c` (BPF 프로그램)와 `sock_prog_roader.c` (로더)의 빌드 및 실행 방법을 설명합니다.

## 1. 사전 준비 (Prerequisites)

BPF CO-RE(Compile Once – Run Everywhere)를 위해 커널 타입 정의 파일인 `vmlinux.h`가 필요합니다.

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

## 2. BPF 프로그램 빌드 (`sock_prog_example.c`)

BPF 프로그램은 `clang`을 사용하여 컴파일합니다. `libbpf`가 BTF 정보를 읽을 수 있도록 반드시 **`-g` 옵션**을 포함해야 합니다.

```bash
clang -O2 -g -target bpf -c sock_prog_example.c -o sock_prog_example.o
```

*   `-O2`: 최적화 레벨 (BPF 검증기를 통과하기 위해 필수)
*   `-g`: 디버그 정보 포함 (BTF 생성에 필수)
*   `-target bpf`: BPF 아키텍처용으로 컴파일
*   `-c`: 오브젝트 파일 생성

## 3. 로더 프로그램 빌드 (`sock_prog_roader.c`)

로더는 사용자 공간 프로그램이므로 `gcc`로 컴파일하며, `libbpf` 라이브러리를 링크해야 합니다.

```bash
gcc -o sock_prog_roader sock_prog_roader.c -lbpf
```

*   `-lbpf`: libbpf 라이브러리 링크

## 4. 실행 방법

빌드된 로더를 실행할 때 BPF 오브젝트 파일을 인자로 전달합니다. (root 권한 필요)

```bash
./sock_prog_roader sock_prog_example.o
```

실행 후 로더는 주기적으로 TCP, UDP, ICMP 패킷 카운트를 출력합니다.
