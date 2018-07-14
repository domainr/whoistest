package whoistest

import (
	"path/filepath"
	"runtime"
)

var (
	_, _file, _, _ = runtime.Caller(0)
	_dir           = filepath.Dir(_file)
)

// ResponseFiles returns a slice of paths to MIME-encoded whois responses.
// Returns nil, error if any errors occur.
func ResponseFiles() ([]string, error) {
	return filepath.Glob(filepath.Join(_dir, "testdata", "responses", "*", "*.mime"))
}

// ResponseFilename returns a fully-qualified path to a response file
// for the given query and host.
func ResponseFilename(query, host string) string {
	return filepath.Join(_dir, "testdata", "responses", host, query+".mime")
}
