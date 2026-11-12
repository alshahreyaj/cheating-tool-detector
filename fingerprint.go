package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

type executableDigest struct {
	sha256 string
	size   int64
	mtime  string
}

var executableDigests = struct {
	sync.RWMutex
	items map[string]executableDigest
}{items: make(map[string]executableDigest)}

func fingerprintExecutable(process *Process, filePath, displayPath string) {
	file, err := os.Open(filePath)
	if err != nil {
		return
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return
	}
	mtime := info.ModTime().UTC().Format("2006-01-02T15:04:05.999999999Z07:00")
	process.ExecutableSize = info.Size()
	process.ExecutableModifiedAt = mtime
	key := fingerprintCacheKey(displayPath, info.Size(), info.ModTime().UnixNano())

	executableDigests.RLock()
	digest, ok := executableDigests.items[key]
	executableDigests.RUnlock()
	if !ok {
		hash := sha256.New()
		if _, err := io.Copy(hash, file); err != nil {
			return
		}
		after, err := file.Stat()
		if err != nil || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
			return
		}
		digest = executableDigest{sha256: fmt.Sprintf("%x", hash.Sum(nil)), size: info.Size(), mtime: mtime}
		executableDigests.Lock()
		if len(executableDigests.items) >= 4096 {
			executableDigests.items = make(map[string]executableDigest)
		}
		executableDigests.items[key] = digest
		executableDigests.Unlock()
	}
	process.ExecutableSHA256 = digest.sha256
	process.ExecutableSize = digest.size
	process.ExecutableModifiedAt = digest.mtime
}

func fingerprintCacheKey(path string, size, modified int64) string {
	path = filepath.Clean(path)
	if runtime.GOOS == "windows" {
		path = strings.ToLower(path)
	}
	return fmt.Sprintf("%s|%d|%d", path, size, modified)
}
