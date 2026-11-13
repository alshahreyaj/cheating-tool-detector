# Developer Guide

This guide describes the detector's signals, rule format, local build, and release workflow. For end-user installation and operation, see the [README](README.md).

## Scope and limits

The app combines two kinds of signals:

1. **Application indicators** compare running process names, executable locations, or exact file fingerprints with configured rules. Built-in rules cover selected remote access and memory inspection or debugging tools.
2. **Windows capture exclusion** reports top-level windows marked with a standard Windows display-affinity setting that keeps them out of supported capture paths. It correlates each window with its owning process.

The second signal works independently of the process-name rules, so it can identify an app that is unknown to the built-in list if its window uses the recognized Windows setting. It does not reveal every way an app can hide from a particular recorder. Linux has no portable system-wide equivalent in this app; Linux scans use application indicators only. Neither signal proves misconduct.

## Scan flow

1. The platform-specific process reader collects process names, PIDs, and executable paths when available.
2. The scanner compares process names and paths with the rules. Matching is case-insensitive substring matching. SHA-256 rules compare the complete file fingerprint.
3. Matching executables are fingerprinted when possible. If a custom SHA-256 rule exists, visible executables are fingerprinted so they can be compared with it. Fingerprints are cached by path, file size, and modification time during the app session.
4. On Windows, the scanner enumerates top-level windows, checks their display affinity, and associates each matching window with its PID and process details. It reports `WDA_MONITOR` and `WDA_EXCLUDEFROMCAPTURE`.
5. The desktop app groups signals for the same PID into one row. **Details** shows the rule/signal and available path and fingerprint. **End task** asks for confirmation and checks the process identity again before acting.

### Platform process readers

- `process_windows.go` uses `tasklist.exe` for names and PIDs, starts it without a console window, then uses `QueryFullProcessImageNameW` for paths. Window ownership comes from `GetWindowThreadProcessId`; display affinity comes from `GetWindowDisplayAffinity`.
- `process_linux.go` reads names from `/proc/<pid>/comm` and paths from `/proc/<pid>/exe`. Access depends on the current user's `/proc` visibility.
- `process_unsupported.go` provides an unsupported-platform response for other operating systems.

Window affinity is a review signal, not proof of cheating. Legitimate apps use capture exclusion for protected content and privacy. The detector does not inspect screen output, process memory, or browser tabs.

## Built-in and custom rules

The defaults are embedded from [`rules.example.json`](rules.example.json), so end users do not need a separate rules file. The current defaults include selected names for AnyDesk, TeamViewer, RustDesk, Cheat Engine, GameConqueror, scanmem, x64dbg, x32dbg, and OllyDbg. This is a starter list, not an exhaustive catalog.

Custom rules replace the built-in rules when `-rules` is supplied. A rule must have a name and at least one indicator:

```json
{
  "rules": [
    {
      "name": "Example application",
      "contains": ["example-process"],
      "executable_contains": ["/opt/example/app"],
      "sha256": ["0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"]
    }
  ]
}
```

- `contains`: case-insensitive substring of the process name.
- `executable_contains`: case-insensitive substring of the executable path.
- `sha256`: exact 64-character hexadecimal SHA-256 digest, compared without regard to letter case.

The example digest is only a format example and does not identify a real program. A process can produce multiple findings if it matches multiple indicators.

## Desktop app and history

The desktop interface is a native [Fyne](https://fyne.io/) app. It starts with a scan interval of 30 seconds; users can set an interval from 5 to 3600 seconds and change it while monitoring. Monitoring scans immediately, then repeats. The tray icon is in alert state while a match is present. A desktop notification is sent when a new process or capture-excluded window is detected.

The app writes history to `os.UserConfigDir()/cheating-tool-detector/detection-history.json`. It records flagged applications appearing, disappearing, changing detection status, and changing executable fingerprint. The file retains up to 2,000 events; the interface displays the latest 100. Ordinary unflagged processes are not kept as history events. History is local and scan results are not sent to a service.

Ending a task is platform-specific. Linux sends `SIGTERM`; Windows uses Go's process termination call. The UI confirms before acting, rechecks process identity, and refuses Windows PID 4. Terminating a process can lose unsaved work and can fail if the current account lacks permission.

## Command-line mode

The normal launch opens the desktop interface. Use `-cli` to scan in a terminal:

```sh
./detector -cli
./detector -cli -json
./detector -cli -watch 5s
./detector -cli -rules rules.json
```

`-json` prints the report as JSON. `-watch` accepts a Go duration, such as `5s` or `1m`, and repeats scans at that interval. In a one-time CLI scan, the process exits with status `0` when there are no findings, `2` when a finding exists, and `1` for a scan or configuration error.

## Build locally

Use Go 1.22 or newer and a C compiler. Fyne's native desktop interface uses CGo.

### Linux

On Debian or Ubuntu, install the desktop build dependencies:

```sh
sudo apt-get install gcc libgl1-mesa-dev xorg-dev libwayland-dev libxkbcommon-dev
go build -o detector .
```

Run the binary with `./detector`.

### Windows

Install Go and a CGo-compatible C compiler such as MinGW-w64 GCC. From a Go-enabled terminal:

```powershell
go build -ldflags="-H=windowsgui" -o detector.exe .
```

`-H=windowsgui` prevents the app itself from opening a console window. The process-list helper is also launched without showing its console.

## Build and publish releases

The [`build.yml`](.github/workflows/build.yml) workflow builds 64-bit Linux and Windows binaries on native GitHub-hosted runners. Pushes to `main`, pull requests, and manual workflow runs create downloadable artifacts. Pushing a version tag runs both builds and then creates a GitHub Release with the binaries attached:

```sh
git tag -a v0.2.0 -m "Release v0.2.0"
git push origin main
git push origin v0.2.0
```

The artifacts are named `detector-linux-amd64` and `detector-windows-amd64.exe`.

## Main source files

| File | Purpose |
| --- | --- |
| `main.go` | Rule loading, scan orchestration, report types, and CLI mode |
| `rules.example.json` | Embedded default process indicators |
| `process_windows.go` | Windows process inventory and capture-excluded window detection |
| `process_linux.go` | Linux process inventory |
| `fingerprint.go` | Executable SHA-256 calculation and in-session cache |
| `history.go` | Local detection history and state changes |
| `ui.go` | Desktop window, monitoring controls, results, notifications, and tray |
| `.github/workflows/build.yml` | Linux/Windows build artifacts and tagged releases |
