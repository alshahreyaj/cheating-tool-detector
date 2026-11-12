package main

import (
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

//go:embed rules.example.json
var embeddedDefaultRules []byte

type Process struct {
	PID                  int    `json:"pid"`
	Name                 string `json:"name"`
	ExecutablePath       string `json:"executable_path,omitempty"`
	ExecutableSHA256     string `json:"executable_sha256,omitempty"`
	ExecutableSize       int64  `json:"executable_size,omitempty"`
	ExecutableModifiedAt string `json:"executable_modified_at,omitempty"`
}

type Rule struct {
	Name               string   `json:"name"`
	Contains           []string `json:"contains,omitempty"`
	ExecutableContains []string `json:"executable_contains,omitempty"`
	SHA256             []string `json:"sha256,omitempty"`
}

type RuleSet struct {
	Rules []Rule `json:"rules"`
}

type Finding struct {
	PID              int    `json:"pid"`
	Process          string `json:"process"`
	Rule             string `json:"rule"`
	MatchType        string `json:"match_type"`
	Indicator        string `json:"indicator"`
	ExecutablePath   string `json:"executable_path,omitempty"`
	ExecutableSHA256 string `json:"executable_sha256,omitempty"`
}

type CaptureExclusion struct {
	PID              int    `json:"pid"`
	Process          string `json:"process,omitempty"`
	ExecutablePath   string `json:"executable_path,omitempty"`
	ExecutableSHA256 string `json:"executable_sha256,omitempty"`
	Window           string `json:"window"`
	Affinity         string `json:"affinity"`
}

type Report struct {
	ScannedAt         string             `json:"scanned_at"`
	Platform          string             `json:"platform"`
	Scanned           int                `json:"processes_scanned"`
	Findings          []Finding          `json:"findings"`
	CaptureExclusions []CaptureExclusion `json:"capture_exclusions"`
	History           []HistoryEvent     `json:"history,omitempty"`
	HistoryError      string             `json:"history_error,omitempty"`
	ProcessInventory  []Process          `json:"-"`
}

func main() {
	rulesPath := flag.String("rules", "", "optional path to JSON process-name rules (defaults are built in)")
	cliMode := flag.Bool("cli", false, "run a terminal scan instead of opening the desktop interface")
	jsonOutput := flag.Bool("json", false, "write each scan as JSON")
	watch := flag.Duration("watch", 0, "repeat scans at this interval (for example 5s); 0 scans once")
	flag.Parse()
	if *watch < 0 {
		fatal("-watch must be zero or greater")
	}

	rules, err := loadRules(*rulesPath)
	if err != nil {
		fatal(err.Error())
	}
	if !*cliMode {
		runDesktopApp(rules)
		return
	}
	matched := false
	for {
		report, err := scan(rules)
		if err != nil {
			fatal(err.Error())
		}
		matched = matched || len(report.Findings) > 0 || len(report.CaptureExclusions) > 0
		if *jsonOutput {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(report); err != nil {
				fatal(err.Error())
			}
		} else {
			printReport(report)
		}
		if *watch == 0 {
			break
		}
		time.Sleep(*watch)
	}
	if matched {
		os.Exit(2)
	}
}

func loadRules(path string) (RuleSet, error) {
	b := embeddedDefaultRules
	if path != "" {
		var err error
		b, err = os.ReadFile(path)
		if err != nil {
			return RuleSet{}, fmt.Errorf("read rules file %q: %w", path, err)
		}
	}
	var set RuleSet
	if err := json.Unmarshal(b, &set); err != nil {
		if path == "" {
			return RuleSet{}, fmt.Errorf("parse built-in rules: %w", err)
		}
		return RuleSet{}, fmt.Errorf("parse rules file %q: %w", path, err)
	}
	for i, rule := range set.Rules {
		if strings.TrimSpace(rule.Name) == "" || (len(rule.Contains) == 0 && len(rule.ExecutableContains) == 0 && len(rule.SHA256) == 0) {
			return RuleSet{}, fmt.Errorf("rule %d must have a name and at least one process, executable, or SHA-256 indicator", i+1)
		}
		for _, value := range append(append(append([]string{}, rule.Contains...), rule.ExecutableContains...), rule.SHA256...) {
			if strings.TrimSpace(value) == "" {
				return RuleSet{}, fmt.Errorf("rule %q has an empty indicator", rule.Name)
			}
		}
		for _, digest := range rule.SHA256 {
			if len(digest) != 64 {
				return RuleSet{}, fmt.Errorf("rule %q has a SHA-256 indicator that is not 64 hexadecimal characters", rule.Name)
			}
			if _, err := hex.DecodeString(digest); err != nil {
				return RuleSet{}, fmt.Errorf("rule %q has an invalid SHA-256 indicator: %w", rule.Name, err)
			}
		}
	}
	return set, nil
}

func scan(rules RuleSet) (Report, error) {
	processes, err := listProcesses()
	if err != nil {
		return Report{}, err
	}
	report := Report{ScannedAt: time.Now().UTC().Format(time.RFC3339), Platform: platformName, Scanned: len(processes), Findings: []Finding{}, CaptureExclusions: []CaptureExclusion{}}
	requiresHash := false
	for _, rule := range rules.Rules {
		requiresHash = requiresHash || len(rule.SHA256) > 0
	}
	for i := range processes {
		process := &processes[i]
		needsFingerprint := requiresHash
		for _, rule := range rules.Rules {
			for _, indicator := range rule.Contains {
				needsFingerprint = needsFingerprint || strings.Contains(strings.ToLower(process.Name), strings.ToLower(indicator))
			}
			for _, indicator := range rule.ExecutableContains {
				needsFingerprint = needsFingerprint || (process.ExecutablePath != "" && strings.Contains(strings.ToLower(process.ExecutablePath), strings.ToLower(indicator)))
			}
		}
		if needsFingerprint {
			fingerprintProcess(process)
		}
		for _, rule := range rules.Rules {
			for _, indicator := range rule.Contains {
				if strings.Contains(strings.ToLower(process.Name), strings.ToLower(indicator)) {
					report.Findings = append(report.Findings, findingFor(*process, rule.Name, "process_name", indicator))
				}
			}
			for _, indicator := range rule.ExecutableContains {
				if process.ExecutablePath != "" && strings.Contains(strings.ToLower(process.ExecutablePath), strings.ToLower(indicator)) {
					report.Findings = append(report.Findings, findingFor(*process, rule.Name, "executable_path", indicator))
				}
			}
			for _, indicator := range rule.SHA256 {
				if process.ExecutableSHA256 != "" && strings.EqualFold(process.ExecutableSHA256, indicator) {
					report.Findings = append(report.Findings, findingFor(*process, rule.Name, "sha256", indicator))
				}
			}
		}
	}
	exclusions, err := listCaptureExclusions(processes)
	if err != nil {
		return Report{}, err
	}
	processIndexes := make(map[int]int, len(processes))
	for i, process := range processes {
		processIndexes[process.PID] = i
	}
	for i := range exclusions {
		if processIndex, ok := processIndexes[exclusions[i].PID]; ok {
			process := &processes[processIndex]
			fingerprintProcess(process)
			exclusions[i].Process = process.Name
			exclusions[i].ExecutablePath = process.ExecutablePath
			exclusions[i].ExecutableSHA256 = process.ExecutableSHA256
		}
	}
	report.CaptureExclusions = exclusions
	report.ProcessInventory = processes
	processByPID := make(map[int]Process, len(processes))
	for _, process := range processes {
		processByPID[process.PID] = process
	}
	if err := recordHistory(&report, processByPID); err != nil {
		report.HistoryError = err.Error()
	}
	return report, nil
}

func findingFor(process Process, rule, matchType, indicator string) Finding {
	return Finding{
		PID: process.PID, Process: process.Name, Rule: rule, MatchType: matchType,
		Indicator: indicator, ExecutablePath: process.ExecutablePath, ExecutableSHA256: process.ExecutableSHA256,
	}
}

func printReport(report Report) {
	fmt.Printf("Scanned %d processes on %s at %s\n", report.Scanned, report.Platform, report.ScannedAt)
	if len(report.Findings) == 0 {
		fmt.Println("No configured indicators matched.")
	} else {
		fmt.Printf("Found %d indicator match(es):\n", len(report.Findings))
		for _, finding := range report.Findings {
			fmt.Printf("  PID %-7d %-24s rule=%q %s=%q\n", finding.PID, finding.Process, finding.Rule, finding.MatchType, finding.Indicator)
			if finding.ExecutablePath != "" {
				fmt.Printf("    executable=%q sha256=%s\n", finding.ExecutablePath, finding.ExecutableSHA256)
			}
		}
	}
	for _, exclusion := range report.CaptureExclusions {
		fmt.Printf("  Capture exclusion: PID %-7d %-24s window=%q affinity=%s\n", exclusion.PID, exclusion.Process, exclusion.Window, exclusion.Affinity)
		if exclusion.ExecutablePath != "" {
			fmt.Printf("    executable=%q sha256=%s\n", exclusion.ExecutablePath, exclusion.ExecutableSHA256)
		}
	}
	if report.HistoryError != "" {
		fmt.Fprintln(os.Stderr, "warning: detection history could not be saved:", report.HistoryError)
	}
}

func fatal(message string) {
	fmt.Fprintln(os.Stderr, "error:", message)
	os.Exit(1)
}
