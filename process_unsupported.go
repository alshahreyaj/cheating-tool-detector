//go:build !linux && !windows

package main

import (
	"fmt"
	"runtime"
)

const platformName = runtime.GOOS

func listProcesses() ([]Process, error) {
	return nil, fmt.Errorf("unsupported platform: %s (supported: linux, windows)", runtime.GOOS)
}

func listCaptureExclusions([]Process) ([]CaptureExclusion, error) {
	return []CaptureExclusion{}, nil
}

func fingerprintProcess(*Process) {}

func endTrackedProcess(int, string, string) error {
	return fmt.Errorf("ending applications is not supported on %s", runtime.GOOS)
}
