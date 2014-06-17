package main

import (
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"

	"code.google.com/p/go.net/idna"
	_ "github.com/domainr/go-whois/servers"
	"github.com/domainr/go-whois/whois"
)

var (
	v, quick       bool
	oneZone        string
	concurrency    int
	zones          []string
	prefixes       []string
	_, _file, _, _ = runtime.Caller(0)
	_dir           = filepath.Dir(_file)
)

func init() {
	flag.BoolVar(&v, "v", false, "verbose output (to stderr)")
	flag.BoolVar(&quick, "quick", false, "Only query a shorter subset of zones")
	flag.StringVar(&oneZone, "zone", "", "Only query a specific zone")
	flag.IntVar(&concurrency, "concurrency", 32, "Set maximum number of concurrent requests")
}

func main() {
	flag.Parse()

	if err := main1(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func main1() error {
	var err error
	zones, err = readLines("zones.txt")
	if err != nil {
		return err
	}
	prefixes, err = readLines("prefixes.txt")
	if err != nil {
		return err
	}

	// Quick for debugging?
	if quick {
		fmt.Fprintf(os.Stderr, "Quick mode enabled\n")
		zones = []string{"com", "net", "org", "co", "io", "nr", "kr", "jp"}
		concurrency = 4 // Don’t slam the .org whois server
	}

	// One zone?
	if oneZone != "" {
		fmt.Fprintf(os.Stderr, "Querying single zone: %s\n", oneZone)
		zones = []string{oneZone}
		concurrency = 1
	}

	re := regexp.MustCompile(`^[^\.]+\.`)

	domains := make(map[string]bool, len(zones)*len(prefixes))
	for _, zone := range zones {
		for _, prefix := range prefixes {
			domain := prefix + "." + zone
			domains[domain] = true
			req, err := whois.Resolve(domain)
			if err == nil {
				hostParent := re.ReplaceAllLiteralString(req.Host, "")
				if _, ok := domains[hostParent]; !ok && hostParent != "" {
					fmt.Fprintf(os.Stderr, "  + %s\n", hostParent)
					domains[hostParent] = true
				}
			}
		}
	}

	fmt.Fprintf(os.Stderr, "Querying whois for %d domains (%d prefixes × %d zones + extras)\n", len(domains), len(prefixes), len(zones))

	responses := make(chan *whois.Response)
	limiter := make(chan struct{}, concurrency) // semaphore to limit concurrency
	for domain, _ := range domains {
		go func(domain string) {
			var res *whois.Response

			limiter <- struct{}{} // acquire semaphore
			defer func() {        // release semaphore
				responses <- res
				<-limiter
			}()

			req, err := whois.Resolve(domain)
			if err != nil {
				return
			}

			if v {
				fmt.Fprintf(os.Stderr, "Fetching %s from %s\n", req.Query, req.Host)
			}
			res, err = req.Fetch()
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error fetching whois for %s: %s\n", req.Query, err)
				return
			}
		}(domain)
	}

	// Collect from goroutines
	var wg sync.WaitGroup
	wg.Add(len(domains))
	for i := 0; i < len(domains); i++ {
		go func() {
			res := <-responses
			defer wg.Done()

			if res == nil {
				return
			}

			if res.Host == "" {
				fmt.Fprintf(os.Stderr, "Response for %q had no host\n", res.Query)
				return
			}

			if len(res.Body) == 0 {
				fmt.Fprintf(os.Stderr, "Response for %q had empty body\n", res.Query)
				return
			}

			dir := filepath.Join(_dir, "data", "responses", res.Host)
			err := os.MkdirAll(dir, os.ModePerm)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error creating response directory for %s: %s\n", res.Host, err)
				return
			}

			fn := filepath.Join(dir, (sha1hex(res.Body) + ".mime"))
			f, err := os.Create(fn)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error creating response file for %s: %s\n", res.Query, err)
				return
			}
			defer f.Close()
			res.WriteMIME(f)
		}()
	}
	wg.Wait()

	return nil
}

var whitespaceAndComments = regexp.MustCompile(`\s+|#.+$`)

func readLines(fn string) ([]string, error) {
	fmt.Fprintf(os.Stderr, "Reading %s\n", fn)
	f, err := os.Open(filepath.Join(_dir, "data", fn))
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := whitespaceAndComments.ReplaceAllLiteralString(s.Text(), "")
		if line == "" {
			continue
		}
		if line, ierr := idna.ToASCII(line); ierr == nil {
			out = append(out, line)
		}
	}
	return out, s.Err()
}

func sha1hex(buf []byte) string {
	h := sha1.New()
	h.Write(buf)
	return strings.ToLower(hex.EncodeToString(h.Sum(nil)))
}
