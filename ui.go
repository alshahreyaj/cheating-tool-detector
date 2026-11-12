package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/widget"
)

//go:embed assets/logo.png
var detectorLogoPNG []byte

const (
	defaultScanInterval = 30
	minScanInterval     = 5
	maxScanInterval     = 3600
)

type desktopMonitor struct {
	app          fyne.App
	window       fyne.Window
	rules        RuleSet
	tray         desktop.App
	interval     *widget.Entry
	startButton  *widget.Button
	scanButton   *widget.Button
	status       *widget.Label
	results      *widget.Entry
	historyView  *widget.Entry
	logoView     *canvas.Image
	monitoring   bool
	stopTicker   chan struct{}
	scanning     atomic.Bool
	previousKeys map[string]struct{}
	regularIcon  fyne.Resource
	alertIcon    fyne.Resource
}

func runDesktopApp(rules RuleSet) {
	a := app.NewWithID("com.alshahreyaj.cheating-tool-detector")
	monitor := &desktopMonitor{
		app:          a,
		rules:        rules,
		previousKeys: make(map[string]struct{}),
		regularIcon:  makeStatusIcon(false),
		alertIcon:    makeStatusIcon(true),
	}
	a.SetIcon(monitor.regularIcon)
	monitor.buildWindow()
	a.Run()
}

func (m *desktopMonitor) buildWindow() {
	m.window = m.app.NewWindow("Cheating Tool Detector")
	m.window.Resize(fyne.NewSize(720, 540))
	m.window.SetFixedSize(false)

	title := widget.NewLabelWithStyle("Cheating Tool Detector", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	intro := widget.NewLabel("Choose how often to scan. Monitoring starts with an immediate scan, then repeats at your interval.")
	intro.Wrapping = fyne.TextWrapWord
	m.logoView = canvas.NewImageFromResource(m.regularIcon)
	m.logoView.FillMode = canvas.ImageFillContain
	m.logoView.ScaleMode = canvas.ImageScaleSmooth
	header := container.NewHBox(
		container.NewGridWrap(fyne.NewSize(64, 64), m.logoView),
		container.NewVBox(title, intro),
	)

	m.interval = widget.NewEntry()
	m.interval.SetText(strconv.Itoa(m.savedInterval()))
	intervalForm := widget.NewForm(widget.NewFormItem("Scan interval (seconds)", m.interval))
	m.status = widget.NewLabel("Monitoring is stopped")
	m.results = widget.NewMultiLineEntry()
	m.results.Disable()
	m.results.SetText("No scan has run yet. Start monitoring or scan now.")
	m.historyView = widget.NewMultiLineEntry()
	m.historyView.Disable()
	m.historyView.SetText("No detection history yet.")

	m.scanButton = widget.NewButton("Scan now", m.scanNow)
	m.startButton = widget.NewButton("Start monitoring", m.toggleMonitoring)
	note := widget.NewLabel("Matches are indicators for review, not proof of cheating. Capture exclusion checks are available on Windows only.")
	note.Wrapping = fyne.TextWrapWord

	resultsTabs := container.NewAppTabs(
		container.NewTabItem("Current scan", m.results),
		container.NewTabItem("Detection history", m.historyView),
	)
	content := container.NewBorder(
		container.NewVBox(header, intervalForm, container.NewHBox(m.startButton, m.scanButton), m.status),
		note,
		nil,
		nil,
		resultsTabs,
	)
	m.window.SetContent(content)

	if tray, ok := m.app.(desktop.App); ok {
		m.tray = tray
		tray.SetSystemTrayIcon(m.regularIcon)
		showWindow := fyne.NewMenuItem("Show window", func() { m.window.Show() })
		scanItem := fyne.NewMenuItem("Scan now", m.scanNow)
		monitorItem := fyne.NewMenuItem("Start monitoring", m.toggleMonitoring)
		quitItem := fyne.NewMenuItem("Quit", func() { m.app.Quit() })
		tray.SetSystemTrayMenu(fyne.NewMenu("Cheating Tool Detector", showWindow, scanItem, monitorItem, quitItem))
		tray.SetSystemTrayWindow(m.window)
		m.window.SetCloseIntercept(func() { m.window.Hide() })
	}

	m.window.Show()
}

func (m *desktopMonitor) savedInterval() int {
	seconds := m.app.Preferences().IntWithFallback("scan-interval-seconds", defaultScanInterval)
	if seconds < minScanInterval || seconds > maxScanInterval {
		return defaultScanInterval
	}
	return seconds
}

func (m *desktopMonitor) toggleMonitoring() {
	if m.monitoring {
		close(m.stopTicker)
		m.stopTicker = nil
		m.monitoring = false
		m.interval.Enable()
		m.startButton.SetText("Start monitoring")
		m.status.SetText("Monitoring is stopped")
		if m.tray != nil {
			m.tray.SetSystemTrayMenu(fyne.NewMenu("Cheating Tool Detector",
				fyne.NewMenuItem("Show window", func() { m.window.Show() }),
				fyne.NewMenuItem("Scan now", m.scanNow),
				fyne.NewMenuItem("Start monitoring", m.toggleMonitoring),
				fyne.NewMenuItem("Quit", func() { m.app.Quit() }),
			))
		}
		return
	}

	seconds, err := strconv.Atoi(strings.TrimSpace(m.interval.Text))
	if err != nil || seconds < minScanInterval || seconds > maxScanInterval {
		m.status.SetText(fmt.Sprintf("Enter an interval from %d to %d seconds.", minScanInterval, maxScanInterval))
		return
	}
	m.app.Preferences().SetInt("scan-interval-seconds", seconds)
	m.monitoring = true
	m.interval.Disable()
	m.startButton.SetText("Stop monitoring")
	m.status.SetText(fmt.Sprintf("Monitoring every %d seconds…", seconds))
	m.stopTicker = make(chan struct{})
	stop := m.stopTicker
	if m.tray != nil {
		m.tray.SetSystemTrayMenu(fyne.NewMenu("Cheating Tool Detector",
			fyne.NewMenuItem("Show window", func() { m.window.Show() }),
			fyne.NewMenuItem("Scan now", m.scanNow),
			fyne.NewMenuItem("Stop monitoring", m.toggleMonitoring),
			fyne.NewMenuItem("Quit", func() { m.app.Quit() }),
		))
	}
	m.scanNow()
	go func() {
		ticker := time.NewTicker(time.Duration(seconds) * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				m.scanNow()
			case <-stop:
				return
			}
		}
	}()
}

func (m *desktopMonitor) scanNow() {
	if !m.scanning.CompareAndSwap(false, true) {
		return
	}
	fyne.Do(func() {
		m.scanButton.Disable()
		m.status.SetText("Scanning…")
	})
	go func() {
		report, err := scan(m.rules)
		fyne.Do(func() {
			defer m.scanning.Store(false)
			m.scanButton.Enable()
			if err != nil {
				m.status.SetText("Scan failed: " + err.Error())
				m.results.SetText("The scan could not be completed. Check process visibility and try again.")
				return
			}
			m.applyReport(report)
		})
	}()
}

func (m *desktopMonitor) applyReport(report Report) {
	var output strings.Builder
	if len(report.Findings) == 0 {
		output.WriteString("No configured process indicators matched.\n")
	} else {
		output.WriteString("PROCESS INDICATORS\n")
		for _, finding := range report.Findings {
			fmt.Fprintf(&output, "• %s (PID %d) — %s; %s matched %q\n", finding.Process, finding.PID, finding.Rule, finding.MatchType, finding.Indicator)
			writeFingerprintDetails(&output, finding.ExecutablePath, finding.ExecutableSHA256)
		}
	}
	output.WriteString("\nSCREEN-CAPTURE EXCLUSIONS\n")
	if len(report.CaptureExclusions) == 0 {
		if report.Platform == "linux" {
			output.WriteString("This signal is not available on Linux.\n")
		} else {
			output.WriteString("No windows marked with a capture-exclusion affinity.\n")
		}
	} else {
		for _, exclusion := range report.CaptureExclusions {
			processName := exclusion.Process
			if processName == "" {
				processName = "Unknown application"
			}
			fmt.Fprintf(&output, "• %s (PID %d) — %s; window %q\n", processName, exclusion.PID, exclusion.Affinity, exclusion.Window)
			writeFingerprintDetails(&output, exclusion.ExecutablePath, exclusion.ExecutableSHA256)
		}
	}
	m.results.SetText(output.String())
	var historyText strings.Builder
	for i := len(report.History) - 1; i >= 0; i-- {
		event := report.History[i]
		fmt.Fprintf(&historyText, "%s  %s  %s", event.At, event.Event, event.Application)
		if len(event.PIDs) > 0 {
			fmt.Fprintf(&historyText, " (PID(s) %s)", joinPIDs(event.PIDs))
		}
		if len(event.Windows) > 0 {
			fmt.Fprintf(&historyText, "\n  Window(s): %s", strings.Join(event.Windows, ", "))
		}
		if event.FromStatus != "" || event.ToStatus != "" {
			fmt.Fprintf(&historyText, "\n  %s → %s", event.FromStatus, event.ToStatus)
		}
		if event.ExecutablePath != "" {
			fmt.Fprintf(&historyText, "\n  %s", event.ExecutablePath)
		}
		if event.ExecutableSHA256 != "" {
			fmt.Fprintf(&historyText, "\n  SHA-256 %s", event.ExecutableSHA256)
		}
		historyText.WriteString("\n\n")
	}
	if historyText.Len() == 0 {
		historyText.WriteString("No detected applications have been recorded yet.\n")
	}
	if report.HistoryError != "" {
		historyText.WriteString("\nHistory could not be saved: " + report.HistoryError)
	}
	m.historyView.SetText(historyText.String())

	currentKeys := make(map[string]struct{}, len(report.Findings)+len(report.CaptureExclusions))
	var newlyDetected []string
	for _, finding := range report.Findings {
		key := applicationKey(Process{PID: finding.PID, Name: finding.Process, ExecutablePath: finding.ExecutablePath, ExecutableSHA256: finding.ExecutableSHA256})
		if _, alreadySeen := currentKeys[key]; alreadySeen {
			continue
		}
		currentKeys[key] = struct{}{}
		if _, exists := m.previousKeys[key]; !exists {
			newlyDetected = append(newlyDetected, finding.Process)
		}
	}
	for _, exclusion := range report.CaptureExclusions {
		key := applicationKey(Process{PID: exclusion.PID, Name: exclusion.Process, ExecutablePath: exclusion.ExecutablePath, ExecutableSHA256: exclusion.ExecutableSHA256})
		if _, alreadySeen := currentKeys[key]; alreadySeen {
			continue
		}
		currentKeys[key] = struct{}{}
		if _, exists := m.previousKeys[key]; !exists {
			name := exclusion.Process
			if name == "" {
				name = "A window with capture exclusion"
			}
			newlyDetected = append(newlyDetected, name)
		}
	}
	m.previousKeys = currentKeys
	hasAlert := len(currentKeys) > 0
	if hasAlert {
		m.setAlertIcon(true)
	} else {
		m.setAlertIcon(false)
	}
	if len(newlyDetected) > 0 {
		content := newlyDetected[0]
		if len(newlyDetected) > 1 {
			content = fmt.Sprintf("%s and %d more indicator(s)", content, len(newlyDetected)-1)
		}
		m.app.SendNotification(&fyne.Notification{Title: "Cheating tool indicator detected", Content: content})
	}
	status := fmt.Sprintf("Last scan: %s · %d process(es) scanned · %d indicator(s) · %d capture-excluded window(s)",
		time.Now().Format("15:04:05"), report.Scanned, len(report.Findings), len(report.CaptureExclusions))
	if report.HistoryError != "" {
		status += " · history save failed"
	}
	if m.monitoring {
		status = fmt.Sprintf("Monitoring every %s · %s", time.Duration(m.app.Preferences().IntWithFallback("scan-interval-seconds", defaultScanInterval))*time.Second, status)
	}
	m.status.SetText(status)
}

func writeFingerprintDetails(output *strings.Builder, executablePath, sha256 string) {
	if executablePath == "" {
		output.WriteString("  Executable path unavailable to this user.\n")
	} else {
		fmt.Fprintf(output, "  Executable: %s\n", executablePath)
	}
	if sha256 == "" {
		output.WriteString("  SHA-256 fingerprint unavailable.\n")
	} else {
		fmt.Fprintf(output, "  SHA-256: %s\n", sha256)
	}
}

func joinPIDs(pids []int) string {
	values := make([]string, len(pids))
	for i, pid := range pids {
		values[i] = strconv.Itoa(pid)
	}
	return strings.Join(values, ", ")
}

func (m *desktopMonitor) setAlertIcon(alert bool) {
	icon := m.regularIcon
	if alert {
		icon = m.alertIcon
	}
	m.app.SetIcon(icon)
	m.window.SetIcon(icon)
	m.logoView.Resource = icon
	m.logoView.Refresh()
	if m.tray != nil {
		m.tray.SetSystemTrayIcon(icon)
	}
}

func makeStatusIcon(alert bool) fyne.Resource {
	if !alert {
		return fyne.NewStaticResource("detector-logo.png", detectorLogoPNG)
	}
	img, err := png.Decode(bytes.NewReader(detectorLogoPNG))
	if err != nil {
		return fyne.NewStaticResource("detector-logo.png", detectorLogoPNG)
	}
	alertImage := image.NewRGBA(img.Bounds())
	draw.Draw(alertImage, alertImage.Bounds(), img, img.Bounds().Min, draw.Src)
	drawAlertBadge(alertImage)
	var data bytes.Buffer
	_ = png.Encode(&data, alertImage)
	return fyne.NewStaticResource("detector-logo-alert.png", data.Bytes())
}

func drawAlertBadge(img *image.RGBA) {
	width, height := img.Bounds().Dx(), img.Bounds().Dy()
	unit := min(width, height)
	radius := unit / 7
	centerX, centerY := width-radius-12, radius+12
	red := color.RGBA{R: 220, G: 53, B: 69, A: 255}
	white := color.RGBA{R: 255, G: 255, B: 255, A: 255}
	for y := centerY - radius; y <= centerY+radius; y++ {
		for x := centerX - radius; x <= centerX+radius; x++ {
			dx, dy := x-centerX, y-centerY
			if dx*dx+dy*dy <= radius*radius && image.Pt(x, y).In(img.Bounds()) {
				img.Set(x, y, red)
			}
		}
	}
	drawIconLine(img, centerX, centerY-radius/2, centerX, centerY+radius/5, white, max(3, radius/3))
	dotY := centerY + radius/2
	dotRadius := max(3, radius/10)
	for y := dotY - dotRadius; y <= dotY+dotRadius; y++ {
		for x := centerX - dotRadius; x <= centerX+dotRadius; x++ {
			dx, dy := x-centerX, y-dotY
			if dx*dx+dy*dy <= dotRadius*dotRadius && image.Pt(x, y).In(img.Bounds()) {
				img.Set(x, y, white)
			}
		}
	}
}

func drawIconLine(img *image.RGBA, x0, y0, x1, y1 int, c color.Color, thickness int) {
	dx, dy := absInt(x1-x0), -absInt(y1-y0)
	sx, sy := -1, -1
	if x0 < x1 {
		sx = 1
	}
	if y0 < y1 {
		sy = 1
	}
	err := dx + dy
	halfThickness := thickness / 2
	for {
		for ox := -halfThickness; ox <= halfThickness; ox++ {
			for oy := -halfThickness; oy <= halfThickness; oy++ {
				px, py := x0+ox, y0+oy
				if image.Pt(px, py).In(img.Bounds()) {
					img.Set(px, py, c)
				}
			}
		}
		if x0 == x1 && y0 == y1 {
			break
		}
		e2 := 2 * err
		if e2 >= dy {
			err += dy
			x0 += sx
		}
		if e2 <= dx {
			err += dx
			y0 += sy
		}
	}
}

func absInt(value int) int {
	if value < 0 {
		return -value
	}
	return value
}
