package whoistest

import (
	"fmt"
	"os"
	"testing"

	"github.com/domainr/whois"
	"github.com/nbio/st"
)

func TestResponseFiles(t *testing.T) {
	fns, err := ResponseFiles()
	st.Assert(t, err, nil)
	for _, fn := range fns {
		fmt.Printf("%s\n", fn)
		res, err := readMIMEFile(fn)
		st.Refute(t, res, nil)
		st.Assert(t, err, nil)
	}
}

func readMIMEFile(fn string) (*whois.Response, error) {
	f, err := os.Open(fn)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return whois.ReadMIME(f)
}
