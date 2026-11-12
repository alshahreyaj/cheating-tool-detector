//go:build linux

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
