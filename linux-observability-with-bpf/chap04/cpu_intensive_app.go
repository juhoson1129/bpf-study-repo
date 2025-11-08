package main

import (
	"fmt"
	"os"
	"time"
)

// functionC는 CPU를 많이 사용하는 실제 작업 함수입니다.
func functionC() {
	// 간단한 연산을 반복하여 CPU 시간을 소모합니다.
	for i := 0; i < 100000000; i++ {
		_ = i * i
	}
}

// functionB는 functionC를 호출합니다.
func functionB() {
	time.Sleep(50 * time.Millisecond)
	functionC()
}

// functionA는 functionB를 호출합니다.
func functionA() {
	time.Sleep(50 * time.Millisecond)
	functionB()
}

func main() {
	// 프로그램의 PID를 출력하여 profiler.py에 쉽게 전달할 수 있도록 합니다.
	fmt.Printf("Program started with PID: %d\n", os.Getpid())
	fmt.Println("Running a CPU-intensive loop... Press Ctrl+C to stop.")

	// functionA를 무한히 호출하여 지속적으로 스택을 쌓고 CPU를 사용합니다.
	for {
		functionA()
	}
}
