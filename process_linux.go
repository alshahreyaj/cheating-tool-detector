//go:build linux

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

const platformName = "linux"

func listProcesses() ([]Process, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("list /proc: %w", err)
	}
	processes := make([]Process, 0, len(entries))
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || !entry.IsDir() {
			continue
		}
		nameBytes, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "comm"))
		if err != nil { // A process may exit or be hidden while the scan is running.
			continue
		}
		name := strings.TrimSpace(string(nameBytes))
		if name != "" {
			process := Process{PID: pid, Name: name}
			exeLink := filepath.Join("/proc", entry.Name(), "exe")
			if executablePath, err := os.Readlink(exeLink); err == nil {
				process.ExecutablePath = executablePath
			}
			processes = append(processes, process)
		}
	}
	return processes, nil
}

func fingerprintProcess(process *Process) {
	if process.ExecutablePath == "" {
		return
	}
	filePath := filepath.Join("/proc", strconv.Itoa(process.PID), "exe")
	fingerprintExecutable(process, filePath, process.ExecutablePath)
}

func listCaptureExclusions([]Process) ([]CaptureExclusion, error) {
	// Linux has no portable, system-wide window capture-exclusion query.
	return []CaptureExclusion{}, nil
}

func endTrackedProcess(pid int, expectedName, expectedPath string) error {
	if pid <= 1 {
		return fmt.Errorf("invalid process ID")
	}
	processDir := filepath.Join("/proc", strconv.Itoa(pid))
	nameBytes, err := os.ReadFile(filepath.Join(processDir, "comm"))
	if err != nil {
		return fmt.Errorf("process is no longer running: %w", err)
	}
	if expectedPath != "" {
		actualPath, err := os.Readlink(filepath.Join(processDir, "exe"))
		if err != nil || !sameProcessPath(actualPath, expectedPath) {
			return fmt.Errorf("process identity changed since the scan; scan again before ending it")
		}
	} else if !strings.EqualFold(strings.TrimSpace(string(nameBytes)), expectedName) {
		return fmt.Errorf("process identity changed since the scan; scan again before ending it")
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	if err := process.Signal(syscall.SIGTERM); err != nil {
		return fmt.Errorf("send close request: %w", err)
	}
	return nil
}

func sameProcessPath(actual, expected string) bool {
	actual = strings.TrimSuffix(actual, " (deleted)")
	expected = strings.TrimSuffix(expected, " (deleted)")
	return filepath.Clean(actual) == filepath.Clean(expected)
}
