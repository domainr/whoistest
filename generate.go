// +build ignore

package main

import (
	"bufio"

	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sync"

	"code.google.com/p/go.net/idna"
	"github.com/domainr/whois"
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
		zones = []string{"com", "net", "org", "co", "io", "nr", "kr", "jp", "de", "in"}
	}

	// One zone?
	if oneZone != "" {
		fmt.Fprintf(os.Stderr, "Querying single zone: %s\n", oneZone)
		zones = []string{oneZone}
	}

	firstLabel := regexp.MustCompile(`^[^\.]+\.`)

	domains := make(map[string]bool, len(zones)*len(prefixes))
	for _, zone := range zones {
		for _, prefix := range prefixes {
			domain := prefix + "." + zone
			domains[domain] = true
			host, err := whois.Resolve(domain)
			if err == nil {
				parent := firstLabel.ReplaceAllLiteralString(host, "")
				if _, ok := domains[parent]; !ok && parent != "" {
					fmt.Fprintf(os.Stderr, "  + %s\n", parent)
					domains[parent] = true
				}
			}
		}
	}

	fmt.Fprintf(os.Stderr, "Querying whois for %d domains (%d prefixes × %d zones + extras)\n", len(domains), len(prefixes), len(zones))

	responses := make(chan *whois.Response)
	var limiter = make(chan struct{}, concurrency)
	var hostLimiters = make(map[string](chan struct{}))
	m := &sync.RWMutex{}
	for domain, _ := range domains {
		go func(domain string) {
			var res *whois.Response

			req, err := whois.NewRequest(domain)
			if err != nil {
				return
			}

			// Per-host semaphore to limit concurrency
			m.RLock()
			hostLimiter, ok := hostLimiters[req.Host]
			m.RUnlock()
			if !ok {
				m.Lock()
				hostLimiters[req.Host] = make(chan struct{}, 1)
				hostLimiter = hostLimiters[req.Host]
				m.Unlock()
			}
			// Acquire
			hostLimiter <- struct{}{}
			limiter <- struct{}{}
			// Release
			defer func() {
				responses <- res
				<-hostLimiter
				<-limiter
			}()

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

			fn := filepath.Join(dir, (res.Checksum() + ".mime"))
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
