# Cheating Tool Detector

Cheating Tool Detector is a small desktop app for Windows and Linux. It checks running applications for signs that may deserve a closer look, and keeps a local history of the applications it flags.

It is a screening aid, not a way to prove that someone is cheating. A match can have a legitimate explanation, and a tool that is not on its indicator list may not be found.

## What it does

- Runs a scan when you ask, or repeats scans at an interval you choose. The default interval is 30 seconds.
- Comes with ready-to-use indicators, so you do not need to create a rules file to get started.
- Checks application names and, when available, their file locations and file fingerprints.
- On Windows, reports windows that use a standard setting to stay out of supported screen captures, along with the application that owns each window.
- Shows an alert in the app and system tray when it finds a match, and records when flagged applications appear, disappear, or change.
- Works as a desktop app, with an optional command-line mode for people who prefer terminal output.

## How detection works

The app looks at the programs currently running on the device and compares them with its indicators. The built-in list includes names associated with remote access software and common memory inspection or debugging tools. These names are clues for review, not a verdict.

If a program matches, the app includes details that can help identify it, such as its process name, file location, and a SHA-256 fingerprint when available. A fingerprint is a summary of the program file that can distinguish one build from another, even when names are similar. Optional custom rules can check specific names, file locations, or fingerprints.

Windows has an additional check: the app looks for windows marked to be excluded from supported screen capture and connects each window to its owning application. Some legitimate apps use this setting for privacy or protected content. Linux does not provide one standard system-wide way to check this, so this screen-capture check is currently Windows-only.

## Getting started

Launch the app, set the scan interval in seconds, then select **Start monitoring**. It scans right away and continues at the selected interval. Use **Scan now** for a one-time scan. The interval is remembered the next time you open the app.

When a match is found, the app marks its icon and can show a desktop notification. On systems with a tray, closing the window hides the app there; use the tray menu to reopen it or quit.

No rules file is needed for normal use. The optional custom rules file is for administrators who want to add their own indicators. For example:

```json
{
  "rules": [
    { "name": "Example app", "contains": ["example-process"] },
    { "name": "Known file", "executable_contains": ["/opt/example/app"] },
    { "name": "Known build", "sha256": ["paste-a-64-character-file-fingerprint-here"] }
  ]
}
```

Start the app with `-rules rules.json` to use that file. For terminal use, add `-cli`; `-cli -json` prints machine-readable results, and `-cli -watch 5s` repeats scans every five seconds.

## Detection history and privacy

The app keeps its detection history on the device, in the current user's application settings folder. It records flagged applications and changes to their detection status; it does not keep a record of every ordinary running application. The scanner does not send scan results to a server.

## What it cannot detect

This tool only finds indicators it can observe. It may miss browser-based services, renamed or modified programs, and tools that do not match its rules. On Windows, the screen-capture check recognizes a standard Windows setting; it does not reveal every technique or guarantee what a particular recording or sharing app can see. Access restrictions may also prevent the app from identifying some running programs or reading their files.

Treat every result as a prompt to investigate in context, not as proof of misconduct.

## Download or build

Ready-to-run Linux and Windows builds are available as workflow artifacts in the repository's **Actions** tab. Version-tagged builds are attached to GitHub Releases when releases are published. These builds currently target 64-bit PCs.

To build on your own system, install Go 1.22 or newer and a C compiler. The desktop interface also needs graphics development libraries. On Debian or Ubuntu, install them with:

```sh
sudo apt-get install gcc libgl1-mesa-dev xorg-dev libwayland-dev libxkbcommon-dev
```

Then build for the operating system you are using:

```sh
go build -o detector .
```

On Windows, run `go build -ldflags="-H=windowsgui" -o detector.exe .` from a Go-enabled terminal. Cross-building the desktop app requires a compiler and graphics libraries for the target system.
