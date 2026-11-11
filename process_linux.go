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
			processes = append(processes, Process{PID: pid, Name: name})
		}
	}
	return processes, nil
}

func listCaptureExclusions([]Process) ([]CaptureExclusion, error) {
	// Linux has no portable, system-wide window capture-exclusion query.
	return []CaptureExclusion{}, nil
}
