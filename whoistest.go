package whoistest

import (
	"path/filepath"
	"runtime"
)

var (
	_, _file, _, _ = runtime.Caller(0)
	_dir           = filepath.Dir(_file)
)

func ResponseFiles() ([]string, error) {
	return filepath.Glob(filepath.Join(_dir, "data", "responses", "*", "*.mime"))
}
