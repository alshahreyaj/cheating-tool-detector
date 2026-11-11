package main

import (
	"encoding/json"
	_ "embed"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

//go:embed rules.example.json
var embeddedDefaultRules []byte

type Process struct {
	PID  int    `json:"pid"`
	Name string `json:"name"`
}

type Rule struct {
	Name     string   `json:"name"`
	Contains []string `json:"contains"`
}

type RuleSet struct {
	Rules []Rule `json:"rules"`
}

type Finding struct {
	PID       int    `json:"pid"`
	Process   string `json:"process"`
	Rule      string `json:"rule"`
	Indicator string `json:"indicator"`
}

type CaptureExclusion struct {
	PID      int    `json:"pid"`
	Process  string `json:"process,omitempty"`
	Window   string `json:"window"`
	Affinity string `json:"affinity"`
}

type Report struct {
	ScannedAt          string             `json:"scanned_at"`
	Platform           string             `json:"platform"`
	Scanned            int                `json:"processes_scanned"`
	Findings           []Finding          `json:"findings"`
	CaptureExclusions []CaptureExclusion `json:"capture_exclusions"`
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
		if err := serveUI(rules); err != nil {
			fatal(err.Error())
		}
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

func openBrowser(url string) error {
	var command *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		command = exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", url)
	case "linux":
		command = exec.Command("xdg-open", url)
	default:
		return fmt.Errorf("automatic browser launch is unsupported on %s", runtime.GOOS)
	}
	if err := command.Start(); err != nil {
		return err
	}
	go func() { _ = command.Wait() }()
	return nil
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
		if strings.TrimSpace(rule.Name) == "" || len(rule.Contains) == 0 {
			return RuleSet{}, fmt.Errorf("rule %d must have a name and at least one contains indicator", i+1)
		}
		for _, value := range rule.Contains {
			if strings.TrimSpace(value) == "" {
				return RuleSet{}, fmt.Errorf("rule %q has an empty indicator", rule.Name)
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
	for _, process := range processes {
		for _, rule := range rules.Rules {
			for _, indicator := range rule.Contains {
				if strings.Contains(strings.ToLower(process.Name), strings.ToLower(indicator)) {
					report.Findings = append(report.Findings, Finding{PID: process.PID, Process: process.Name, Rule: rule.Name, Indicator: indicator})
				}
			}
		}
	}
	exclusions, err := listCaptureExclusions(processes)
	if err != nil {
		return Report{}, err
	}
	report.CaptureExclusions = exclusions
	return report, nil
}

func printReport(report Report) {
	fmt.Printf("Scanned %d processes on %s at %s\n", report.Scanned, report.Platform, report.ScannedAt)
	if len(report.Findings) == 0 {
		fmt.Println("No configured indicators matched.")
	} else {
		fmt.Printf("Found %d indicator match(es):\n", len(report.Findings))
		for _, finding := range report.Findings {
			fmt.Printf("  PID %-7d %-24s rule=%q indicator=%q\n", finding.PID, finding.Process, finding.Rule, finding.Indicator)
		}
	}
	for _, exclusion := range report.CaptureExclusions {
		fmt.Printf("  Capture exclusion: PID %-7d %-24s window=%q affinity=%s\n", exclusion.PID, exclusion.Process, exclusion.Window, exclusion.Affinity)
	}
}

func fatal(message string) {
	fmt.Fprintln(os.Stderr, "error:", message)
	os.Exit(1)
}
