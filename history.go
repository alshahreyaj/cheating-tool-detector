package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	maxHistoryEvents = 2000
	historyPageSize  = 100
)

type HistoryEvent struct {
	At               string   `json:"at"`
	Event            string   `json:"event"`
	Application      string   `json:"application"`
	ExecutablePath   string   `json:"executable_path,omitempty"`
	ExecutableSHA256 string   `json:"executable_sha256,omitempty"`
	PIDs             []int    `json:"pids,omitempty"`
	Windows          []string `json:"windows,omitempty"`
	FromStatus       string   `json:"from_status,omitempty"`
	ToStatus         string   `json:"to_status,omitempty"`
}

type trackedApplication struct {
	Application      string   `json:"application"`
	ExecutablePath   string   `json:"executable_path,omitempty"`
	ExecutableSHA256 string   `json:"executable_sha256,omitempty"`
	PIDs             []int    `json:"pids,omitempty"`
	Windows          []string `json:"windows,omitempty"`
	Status           string   `json:"status,omitempty"`
	Signals          []string `json:"signals,omitempty"`
}

type historyFile struct {
	Tracked map[string]trackedApplication `json:"tracked_applications"`
	Events  []HistoryEvent                `json:"events"`
}

var localHistory = struct {
	sync.Mutex
	loaded bool
	path   string
	data   historyFile
}{data: historyFile{Tracked: make(map[string]trackedApplication)}}

type applicationObservation struct {
	trackedApplication
	signalSet map[string]struct{}
	pidSet    map[int]struct{}
	windowSet map[string]struct{}
}

func recordHistory(report *Report, processByPID map[int]Process) error {
	localHistory.Lock()
	defer localHistory.Unlock()
	if err := loadHistoryLocked(); err != nil {
		return err
	}

	current := make(map[string]*applicationObservation)
	for _, process := range report.ProcessInventory {
		observation := observationFor(current, process)
		observation.pidSet[process.PID] = struct{}{}
	}
	for _, finding := range report.Findings {
		process := processByPID[finding.PID]
		observation := observationFor(current, process)
		observation.signalSet[finding.Rule+" ("+finding.MatchType+": "+finding.Indicator+")"] = struct{}{}
	}
	for _, exclusion := range report.CaptureExclusions {
		process, ok := processByPID[exclusion.PID]
		if !ok {
			process = Process{PID: exclusion.PID, Name: exclusion.Process, ExecutablePath: exclusion.ExecutablePath, ExecutableSHA256: exclusion.ExecutableSHA256}
		}
		observation := observationFor(current, process)
		observation.signalSet["capture exclusion: "+exclusion.Affinity] = struct{}{}
		if exclusion.Window != "" {
			observation.windowSet[exclusion.Window] = struct{}{}
		}
	}

	keys := make([]string, 0, len(current))
	for key := range current {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	nextTracked := make(map[string]trackedApplication)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, key := range keys {
		observation := current[key]
		state := finalizeObservation(observation)
		previous, wasTracked := localHistory.data.Tracked[key]
		if !wasTracked {
			if state.Status == "" {
				continue // Keep history focused on apps that matched a signal.
			}
			appendHistoryEvent(&localHistory.data, HistoryEvent{
				At: now, Event: "appeared", Application: state.Application,
				ExecutablePath: state.ExecutablePath, ExecutableSHA256: state.ExecutableSHA256,
				PIDs: state.PIDs, Windows: state.Windows, ToStatus: state.Status,
			})
		} else {
			if state.ExecutableSHA256 == "" {
				state.ExecutableSHA256 = previous.ExecutableSHA256
			}
			if previous.ExecutableSHA256 != "" && state.ExecutableSHA256 != "" && previous.ExecutableSHA256 != state.ExecutableSHA256 {
				appendHistoryEvent(&localHistory.data, HistoryEvent{
					At: now, Event: "executable_changed", Application: state.Application,
					ExecutablePath: state.ExecutablePath, ExecutableSHA256: state.ExecutableSHA256,
					PIDs: state.PIDs, Windows: state.Windows, FromStatus: previous.ExecutableSHA256, ToStatus: state.ExecutableSHA256,
				})
			}
			if previous.Status != state.Status {
				appendHistoryEvent(&localHistory.data, HistoryEvent{
					At: now, Event: "status_changed", Application: state.Application,
					ExecutablePath: state.ExecutablePath, ExecutableSHA256: state.ExecutableSHA256,
					PIDs: state.PIDs, Windows: state.Windows, FromStatus: statusLabel(previous.Status), ToStatus: statusLabel(state.Status),
				})
			}
		}
		if wasTracked || state.Status != "" {
			nextTracked[key] = state
		}
	}

	previousKeys := make([]string, 0, len(localHistory.data.Tracked))
	for key := range localHistory.data.Tracked {
		previousKeys = append(previousKeys, key)
	}
	sort.Strings(previousKeys)
	for _, key := range previousKeys {
		if _, stillRunning := current[key]; stillRunning {
			continue
		}
		previous := localHistory.data.Tracked[key]
		appendHistoryEvent(&localHistory.data, HistoryEvent{
			At: now, Event: "disappeared", Application: previous.Application,
			ExecutablePath: previous.ExecutablePath, ExecutableSHA256: previous.ExecutableSHA256,
			PIDs: previous.PIDs, Windows: previous.Windows, FromStatus: statusLabel(previous.Status), ToStatus: "not running",
		})
	}
	localHistory.data.Tracked = nextTracked
	if err := saveHistoryLocked(); err != nil {
		return err
	}
	start := len(localHistory.data.Events) - historyPageSize
	if start < 0 {
		start = 0
	}
	report.History = append([]HistoryEvent{}, localHistory.data.Events[start:]...)
	return nil
}

func observationFor(current map[string]*applicationObservation, process Process) *applicationObservation {
	key := applicationKey(process)
	observation := current[key]
	if observation == nil {
		application := process.Name
		if process.ExecutablePath != "" {
			application = filepath.Base(process.ExecutablePath)
		}
		observation = &applicationObservation{
			trackedApplication: trackedApplication{Application: application, ExecutablePath: process.ExecutablePath, ExecutableSHA256: process.ExecutableSHA256},
			signalSet:          make(map[string]struct{}),
			pidSet:             make(map[int]struct{}),
			windowSet:          make(map[string]struct{}),
		}
		current[key] = observation
	}
	if process.Name != "" && observation.Application == "" {
		observation.Application = process.Name
	}
	if process.ExecutablePath != "" {
		observation.ExecutablePath = process.ExecutablePath
	}
	if process.ExecutableSHA256 != "" {
		observation.ExecutableSHA256 = process.ExecutableSHA256
	}
	if process.PID > 0 {
		observation.pidSet[process.PID] = struct{}{}
	}
	return observation
}

func applicationKey(process Process) string {
	if process.ExecutablePath != "" {
		path := filepath.Clean(process.ExecutablePath)
		if runtime.GOOS == "windows" {
			path = strings.ToLower(path)
		}
		return "path:" + path
	}
	if process.ExecutableSHA256 != "" {
		return "sha256:" + process.ExecutableSHA256
	}
	return fmt.Sprintf("pid:%d:%s", process.PID, strings.ToLower(process.Name))
}

func finalizeObservation(observation *applicationObservation) trackedApplication {
	state := observation.trackedApplication
	for pid := range observation.pidSet {
		state.PIDs = append(state.PIDs, pid)
	}
	sort.Ints(state.PIDs)
	for title := range observation.windowSet {
		state.Windows = append(state.Windows, title)
	}
	sort.Strings(state.Windows)
	for signal := range observation.signalSet {
		state.Signals = append(state.Signals, signal)
	}
	sort.Strings(state.Signals)
	state.Status = strings.Join(state.Signals, "; ")
	return state
}

func statusLabel(status string) string {
	if status == "" {
		return "no active detection"
	}
	return status
}

func appendHistoryEvent(data *historyFile, event HistoryEvent) {
	data.Events = append(data.Events, event)
	if len(data.Events) > maxHistoryEvents {
		data.Events = append([]HistoryEvent{}, data.Events[len(data.Events)-maxHistoryEvents:]...)
	}
}

func loadHistoryLocked() error {
	if localHistory.loaded {
		return nil
	}
	configDir, err := os.UserConfigDir()
	if err != nil {
		return fmt.Errorf("find user config directory: %w", err)
	}
	localHistory.path = filepath.Join(configDir, "cheating-tool-detector", "detection-history.json")
	contents, err := os.ReadFile(localHistory.path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read detection history: %w", err)
	}
	if err == nil {
		if err := json.Unmarshal(contents, &localHistory.data); err != nil {
			return fmt.Errorf("parse detection history: %w", err)
		}
		if localHistory.data.Tracked == nil {
			localHistory.data.Tracked = make(map[string]trackedApplication)
		}
	}
	localHistory.loaded = true
	return nil
}

func saveHistoryLocked() error {
	directory := filepath.Dir(localHistory.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create history directory: %w", err)
	}
	file, err := os.CreateTemp(directory, ".detection-history-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary history file: %w", err)
	}
	temporaryPath := file.Name()
	defer os.Remove(temporaryPath)
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return fmt.Errorf("set history file permissions: %w", err)
	}
	if err := json.NewEncoder(file).Encode(localHistory.data); err != nil {
		_ = file.Close()
		return fmt.Errorf("write detection history: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close detection history: %w", err)
	}
	if err := os.Rename(temporaryPath, localHistory.path); err != nil {
		return fmt.Errorf("replace detection history: %w", err)
	}
	return nil
}
