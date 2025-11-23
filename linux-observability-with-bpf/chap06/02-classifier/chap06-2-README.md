# Chapter 6-2: BPF Traffic Classifier Example

이 문서는 `classifier.c` (TC BPF 프로그램)의 빌드, 적재 및 테스트 방법을 설명합니다. 이 예제는 들어오는 패킷이 HTTP GET 요청인지 감지하여 로그를 출력합니다.

## 1. 빌드 (Build)

`classifier.c`는 커널 헤더(`asm/types.h` 등)를 참조하므로, 컴파일 시 시스템 아키텍처에 맞는 헤더 경로를 포함해야 합니다.

```bash
clang -O2 -target bpf -I/usr/include/$(uname -m)-linux-gnu -c classifier.c -o classifier.o
```

*   `-I/usr/include/$(uname -m)-linux-gnu`: 아키텍처별 헤더 파일 경로 추가 (예: `aarch64-linux-gnu`)

## 2. BPF 프로그램 적재 (Load)

로컬 테스트 시(예: `curl localhost`), 트래픽은 `lo` (Loopback) 인터페이스를 통과합니다. 따라서 `lo` 인터페이스에 필터를 적용해야 합니다.

```bash
# 1. qdisc 추가 (만약 없다면)
tc qdisc add dev lo ingress

# 2. BPF 필터 적용
tc filter add dev lo ingress bpf obj classifier.o flowid 0
```

> **참고**: 외부 트래픽을 테스트하려면 `eth0` 인터페이스에 적용하세요.
> ```bash
> tc qdisc add dev eth0 ingress
> tc filter add dev eth0 ingress bpf obj classifier.o flowid 0
> ```

## 3. 테스트 및 로그 확인

### 3.1 로그 모니터링
별도의 터미널에서 커널 트레이스 파이프를 열어둡니다.

```bash
cat /sys/kernel/debug/tracing/trace_pipe
```

### 3.2 웹 서버 실행 및 요청 전송
간단한 Python 웹 서버를 띄우고 요청을 보냅니다.

**서버 실행:**
```bash
python3 -m http.server 8000
```

**요청 전송 (다른 터미널):**
```bash
curl http://localhost:8000
```

### 3.3 결과 확인
`trace_pipe` 터미널에 다음과 같은 로그가 출력되면 성공입니다.

```text
Yes! It is HTTP!
```

## 4. 정리 (Cleanup)

테스트가 끝나면 필터를 제거합니다.

```bash
tc filter del dev lo ingress
# 또는
tc qdisc del dev lo ingress
```
