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
	kernel32                  = syscall.NewLazyDLL("kernel32.dll")
	openProcess               = kernel32.NewProc("OpenProcess")
	queryFullProcessImageName = kernel32.NewProc("QueryFullProcessImageNameW")
	closeHandle               = kernel32.NewProc("CloseHandle")
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
		process := Process{PID: pid, Name: strings.TrimSpace(row[0])}
		if executablePath := processExecutablePath(pid); executablePath != "" {
			process.ExecutablePath = executablePath
		}
		processes = append(processes, process)
	}
	return processes, nil
}

func fingerprintProcess(process *Process) {
	if process.ExecutablePath != "" {
		fingerprintExecutable(process, process.ExecutablePath, process.ExecutablePath)
	}
}

func processExecutablePath(pid int) string {
	handle, _, _ := openProcess.Call(0x1000, 0, uintptr(pid)) // PROCESS_QUERY_LIMITED_INFORMATION
	if handle == 0 {
		return ""
	}
	defer closeHandle.Call(handle)
	buffer := make([]uint16, 32768)
	length := uint32(len(buffer))
	ok, _, _ := queryFullProcessImageName.Call(handle, 0, uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&length)))
	if ok == 0 || length == 0 {
		return ""
	}
	return syscall.UTF16ToString(buffer[:length])
}

func listCaptureExclusions(processes []Process) ([]CaptureExclusion, error) {
	processByPID := make(map[int]Process, len(processes))
	for _, process := range processes {
		processByPID[process.PID] = process
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
		process := processByPID[int(pid)]
		var title [512]uint16
		length, _, _ := getWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(&title[0])), uintptr(len(title)))
		windowTitle := syscall.UTF16ToString(title[:length])
		affinityName := "WDA_MONITOR"
		if affinity == 0x11 {
			affinityName = "WDA_EXCLUDEFROMCAPTURE"
		}
		exclusions = append(exclusions, CaptureExclusion{
			PID:              int(pid),
			Process:          process.Name,
			ExecutablePath:   process.ExecutablePath,
			ExecutableSHA256: process.ExecutableSHA256,
			Window:           windowTitle,
			Affinity:         affinityName,
		})
		return 1
	})
	result, _, callErr := enumWindows.Call(callback, 0)
	if result == 0 {
		return nil, fmt.Errorf("enumerate desktop windows: %v", callErr)
	}
	return exclusions, nil
}
