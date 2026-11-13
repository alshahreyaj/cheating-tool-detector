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
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/layout"
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
	results      *fyne.Container
	historyView  *fyne.Container
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
	logo := container.NewGridWrap(fyne.NewSize(56, 56), m.logoView)
	header := container.NewBorder(nil, nil, logo, nil, container.NewVBox(title, intro))

	m.interval = widget.NewEntry()
	m.interval.SetText(strconv.Itoa(m.savedInterval()))
	m.interval.OnChanged = m.intervalChanged
	intervalInput := container.NewGridWrap(fyne.NewSize(76, 38), m.interval)
	m.status = widget.NewLabel("Monitoring is stopped")
	m.results = container.NewVBox(widget.NewLabel("No scan has run yet. Start monitoring or scan now."))
	m.historyView = container.NewVBox(widget.NewLabel("No detection history yet."))

	m.scanButton = widget.NewButton("Scan now", m.scanNow)
	m.startButton = widget.NewButton("Start monitoring", m.toggleMonitoring)
	settings := container.NewHBox(
		widget.NewLabel("Scan every"), intervalInput, widget.NewLabel("seconds"),
		m.startButton, m.scanButton,
	)
	note := widget.NewLabel("Matches are indicators for review, not proof of cheating. Capture exclusion checks are available on Windows only.")
	note.Wrapping = fyne.TextWrapWord

	resultsTabs := container.NewAppTabs(
		container.NewTabItem("Current scan", container.NewVScroll(m.results)),
		container.NewTabItem("Detection history", container.NewVScroll(m.historyView)),
	)
	content := container.NewBorder(
		container.NewVBox(header, settings, m.status),
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
	m.startButton.SetText("Stop monitoring")
	m.status.SetText(fmt.Sprintf("Monitoring every %d seconds…", seconds))
	if m.tray != nil {
		m.tray.SetSystemTrayMenu(fyne.NewMenu("Cheating Tool Detector",
			fyne.NewMenuItem("Show window", func() { m.window.Show() }),
			fyne.NewMenuItem("Scan now", m.scanNow),
			fyne.NewMenuItem("Stop monitoring", m.toggleMonitoring),
			fyne.NewMenuItem("Quit", func() { m.app.Quit() }),
		))
	}
	m.startMonitoringTicker(seconds)
	m.scanNow()
}

func (m *desktopMonitor) intervalChanged(value string) {
	if !m.monitoring {
		return
	}
	seconds, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || seconds < minScanInterval || seconds > maxScanInterval {
		m.status.SetText(fmt.Sprintf("Choose an interval from %d to %d seconds; the current interval is unchanged.", minScanInterval, maxScanInterval))
		return
	}
	m.app.Preferences().SetInt("scan-interval-seconds", seconds)
	m.startMonitoringTicker(seconds)
	m.status.SetText(fmt.Sprintf("Monitoring every %d seconds", seconds))
}

func (m *desktopMonitor) startMonitoringTicker(seconds int) {
	if m.stopTicker != nil {
		close(m.stopTicker)
	}
	m.stopTicker = make(chan struct{})
	stop := m.stopTicker
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
				m.results.RemoveAll()
				m.results.Add(widget.NewCard("Scan failed", "Check process visibility and try again.", widget.NewLabel(err.Error())))
				return
			}
			m.applyReport(report)
		})
	}()
}

func (m *desktopMonitor) applyReport(report Report) {
	m.results.RemoveAll()
	items := make(map[int]*reviewItem)
	var orderedItems []*reviewItem
	getItem := func(process Process) *reviewItem {
		if item, ok := items[process.PID]; ok {
			if item.Process.ExecutablePath == "" {
				item.Process.ExecutablePath = process.ExecutablePath
			}
			if item.Process.ExecutableSHA256 == "" {
				item.Process.ExecutableSHA256 = process.ExecutableSHA256
			}
			return item
		}
		item := &reviewItem{Process: process}
		items[process.PID] = item
		orderedItems = append(orderedItems, item)
		return item
	}
	for _, finding := range report.Findings {
		item := getItem(Process{PID: finding.PID, Name: finding.Process, ExecutablePath: finding.ExecutablePath, ExecutableSHA256: finding.ExecutableSHA256})
		item.Signals = append(item.Signals, fmt.Sprintf("%s: %s matched %q", finding.Rule, finding.MatchType, finding.Indicator))
	}
	for _, exclusion := range report.CaptureExclusions {
		name := exclusion.Process
		if name == "" {
			name = "Unknown application"
		}
		item := getItem(Process{PID: exclusion.PID, Name: name, ExecutablePath: exclusion.ExecutablePath, ExecutableSHA256: exclusion.ExecutableSHA256})
		item.Signals = append(item.Signals, fmt.Sprintf("Window excluded from capture (%s): %q", exclusion.Affinity, exclusion.Window))
	}
	if len(orderedItems) == 0 {
		m.results.Add(widget.NewCard("No matches", "No configured indicators matched.", nil))
	} else {
		m.results.Add(widget.NewLabelWithStyle(fmt.Sprintf("Applications to review · %d", len(orderedItems)), fyne.TextAlignLeading, fyne.TextStyle{Bold: true}))
		for _, item := range orderedItems {
			m.results.Add(m.reviewCard(item))
		}
	}
	if report.Platform == "linux" {
		m.results.Add(widget.NewLabel("Screen-capture exclusion checks are not available on Linux."))
	}
	m.historyView.RemoveAll()
	if len(report.History) == 0 && report.HistoryError == "" {
		m.historyView.Add(widget.NewLabel("No detection history yet."))
	} else {
		for i := len(report.History) - 1; i >= 0; i-- {
			event := report.History[i]
			details := []string{formatHistoryTime(event.At)}
			if len(event.PIDs) > 0 {
				details = append(details, "PID(s) "+joinPIDs(event.PIDs))
			}
			if len(event.Windows) > 0 {
				details = append(details, "Window(s): "+strings.Join(event.Windows, ", "))
			}
			if event.FromStatus != "" || event.ToStatus != "" {
				details = append(details, event.FromStatus+" → "+event.ToStatus)
			}
			if event.ExecutablePath != "" {
				details = append(details, event.ExecutablePath)
			}
			if event.ExecutableSHA256 != "" {
				details = append(details, "SHA-256: "+event.ExecutableSHA256)
			}
			m.historyView.Add(m.historyCard(event, strings.Join(details, "\n")))
		}
		if report.HistoryError != "" {
			m.historyView.Add(widget.NewLabel("History could not be saved: " + report.HistoryError))
		}
	}

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

type reviewItem struct {
	Process Process
	Signals []string
}

func (m *desktopMonitor) reviewCard(item *reviewItem) fyne.CanvasObject {
	process := item.Process
	name := process.Name
	if name == "" {
		name = "Unknown application"
	}
	details := []string{strings.Join(item.Signals, "\n")}
	if process.ExecutablePath != "" {
		details = append(details, "File: "+process.ExecutablePath)
	}
	if process.ExecutableSHA256 != "" {
		details = append(details, "SHA-256: "+process.ExecutableSHA256)
	}
	info := strings.Join(details, "\n")
	nameLabel := widget.NewLabelWithStyle(name, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	pidLabel := widget.NewLabel(fmt.Sprintf("PID %d", process.PID))
	showDetails := widget.NewButton("Details", func() {
		dialog.NewInformation("Application details", info, m.window).Show()
	})
	actions := []fyne.CanvasObject{showDetails}
	if process.PID > 0 && process.Name != "Unknown application" {
		actions = append(actions, widget.NewButton("End task", func() { m.confirmEndTask(process) }))
	}
	mainRow := container.NewHBox(nameLabel, pidLabel, layout.NewSpacer(), container.NewHBox(actions...))
	signal := item.Signals[0]
	if len(item.Signals) > 1 {
		signal += fmt.Sprintf(" · +%d more signal(s)", len(item.Signals)-1)
	}
	signalLabel := widget.NewLabel(signal)
	signalLabel.Wrapping = fyne.TextWrapWord
	return widget.NewCard("", "", container.NewVBox(mainRow, signalLabel))
}

func (m *desktopMonitor) historyCard(event HistoryEvent, details string) fyne.CanvasObject {
	application := widget.NewLabelWithStyle(event.Application, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	metadata := widget.NewLabel(event.Event + " · " + formatHistoryTime(event.At))
	showDetails := widget.NewButton("Details", func() {
		dialog.NewInformation("Detection history", details, m.window).Show()
	})
	row := container.NewHBox(container.NewVBox(application, metadata), layout.NewSpacer(), showDetails)
	return widget.NewCard("", "", row)
}

func formatHistoryTime(value string) string {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return value
	}
	return parsed.Local().Format("Jan 2, 2006 · 3:04 PM")
}

func (m *desktopMonitor) confirmEndTask(process Process) {
	dialog.NewConfirm("End application?",
		fmt.Sprintf("End %s (PID %d)? The application may lose unsaved work.", process.Name, process.PID),
		func(confirmed bool) {
			if !confirmed {
				return
			}
			m.status.SetText("Requesting application to end…")
			go func() {
				err := endTrackedProcess(process.PID, process.Name, process.ExecutablePath)
				fyne.Do(func() {
					if err != nil {
						m.status.SetText("Could not end application: " + err.Error())
						return
					}
					m.status.SetText("End request sent. Refreshing the scan…")
					m.scanNow()
				})
			}()
		}, m.window).Show()
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
