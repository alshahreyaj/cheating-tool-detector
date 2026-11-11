# cheating-tool-detector

A small process-indicator scanner for Linux and Windows, with a browser-based local desktop interface and an optional command-line mode. The interface and default rules are embedded in the binary; custom JSON rules are optional.

## Build

Install Go 1.22 or newer, then build for the current platform:

```sh
go build -o detector .
```

To cross-compile:

```sh
GOOS=linux GOARCH=amd64 go build -o detector-linux .
GOOS=windows GOARCH=amd64 go build -o detector.exe .
```

GitHub Actions builds Linux and Windows amd64 binaries on pushes, pull requests, and manual runs. Open the workflow run in the repository's **Actions** tab to download its build artifacts. To publish downloadable binaries on a GitHub Release, create and push a version tag:

```sh
git tag v0.1.0
git push origin v0.1.0
```

The tagged workflow attaches `detector-linux-amd64` and `detector-windows-amd64.exe` to the generated release.

## Run

The default command starts the local desktop interface in your browser. It has built-in indicators, so no rules file is needed:

```sh
./detector
```

Keep the terminal open while using the interface. It listens only on localhost. For terminal output instead, use `-cli`:

```sh
./detector -cli
./detector -cli -json
./detector -cli -watch 5s
```

To provide custom indicators, pass a JSON rules file in either mode: `./detector -rules rules.json`.

Each rule has a display name and one or more case-insensitive substrings matched against the process name. A process can produce more than one finding if it matches multiple indicators. In CLI mode, the program exits with status `0` when there are no matches, `2` when there is at least one match, and `1` if scanning or configuration fails.

On Linux, names are read from `/proc/<pid>/comm`. On Windows, the built-in `tasklist.exe` command supplies process names and PIDs. Processes that disappear during a scan are skipped where possible.

On Windows, the scanner also enumerates top-level windows and checks `GetWindowDisplayAffinity`. It reports windows marked `WDA_EXCLUDEFROMCAPTURE` (and the related `WDA_MONITOR` mode), including the owning PID and window title where available. This can surface apps that intentionally keep their window out of supported capture paths even when their process name does not match a rule. It is only a review signal: legitimate apps use this setting too, and Microsoft documents it as a content-protection aid rather than a security boundary. Linux currently has no portable system-wide query for per-window capture exclusion, so this signal is Windows-only.

## Limits

This is an indicator scanner, not proof of cheating. The sample rules are illustrative and may produce false positives; maintain rules appropriate to your environment. Process-name matching will not detect browser-based services or renamed tools. It does not inspect process memory, capture screens, or collect command lines. Linux visibility depends on `/proc` permissions, and Windows results depend on the current account's process visibility. Window-affinity checking only finds apps using the standard Windows API and does not detect every way an app might be absent from a particular recorder's output.
