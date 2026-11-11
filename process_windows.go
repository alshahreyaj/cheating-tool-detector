//go:build windows

package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

const platformName = "windows"

var (
	user32                    = syscall.NewLazyDLL("user32.dll")
	enumWindows               = user32.NewProc("EnumWindows")
	getWindowDisplayAffinity  = user32.NewProc("GetWindowDisplayAffinity")
	getWindowThreadProcessID  = user32.NewProc("GetWindowThreadProcessId")
	getWindowTextW            = user32.NewProc("GetWindowTextW")
)

func listProcesses() ([]Process, error) {
	output, err := exec.Command("tasklist.exe", "/FO", "CSV", "/NH").Output()
	if err != nil {
		return nil, fmt.Errorf("run tasklist.exe: %w", err)
	}
	reader := csv.NewReader(strings.NewReader(string(output)))
	reader.FieldsPerRecord = -1
	processes := make([]Process, 0)
	for {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parse tasklist output: %w", err)
		}
		if len(row) < 2 {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(row[1]))
		if err != nil { // Ignore localized status/error lines from tasklist.
			continue
		}
		processes = append(processes, Process{PID: pid, Name: strings.TrimSpace(row[0])})
	}
	return processes, nil
}

func listCaptureExclusions(processes []Process) ([]CaptureExclusion, error) {
	processNames := make(map[int]string, len(processes))
	for _, process := range processes {
		processNames[process.PID] = process.Name
	}
	var exclusions []CaptureExclusion
	callback := syscall.NewCallback(func(hwnd, _ uintptr) uintptr {
		var affinity uint32
		ok, _, _ := getWindowDisplayAffinity.Call(hwnd, uintptr(unsafe.Pointer(&affinity)))
		if ok == 0 || (affinity != 0x1 && affinity != 0x11) {
			return 1
		}
		var pid uint32
		getWindowThreadProcessID.Call(hwnd, uintptr(unsafe.Pointer(&pid)))
		var title [512]uint16
		length, _, _ := getWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(&title[0])), uintptr(len(title)))
		windowTitle := syscall.UTF16ToString(title[:length])
		affinityName := "WDA_MONITOR"
		if affinity == 0x11 {
			affinityName = "WDA_EXCLUDEFROMCAPTURE"
		}
		exclusions = append(exclusions, CaptureExclusion{
			PID:      int(pid),
			Process:  processNames[int(pid)],
			Window:   windowTitle,
			Affinity: affinityName,
		})
		return 1
	})
	result, _, callErr := enumWindows.Call(callback, 0)
	if result == 0 {
		return nil, fmt.Errorf("enumerate desktop windows: %v", callErr)
	}
	return exclusions, nil
}
