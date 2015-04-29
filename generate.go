// +build ignore

package main

import (
	"bufio"
	"time"

	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"

	"code.google.com/p/go.net/idna"
	"github.com/domainr/whois"
	"github.com/domainr/whoistest"
	"github.com/zonedb/zonedb"
)

var (
	v, quick       bool
	oneZone        string
	maxAge         time.Duration
	concurrency    int
	zones          []string
	prefixes       []string
	firstLabel     = regexp.MustCompile(`^[^\.]+\.`)
	_, _file, _, _ = runtime.Caller(0)
	_dir           = filepath.Dir(_file)
)

func init() {
	flag.BoolVar(&v, "v", false, "verbose output (to stderr)")
	flag.BoolVar(&quick, "quick", false, "Only query a shorter subset of zones")
	flag.StringVar(&oneZone, "zone", "", "Only query a specific zone")
	flag.IntVar(&concurrency, "concurrency", 32, "Set maximum number of concurrent requests")
	flag.DurationVar(&maxAge, "maxage", (24 * time.Hour * 30), "Set max age of responses before re-fetching")
}

func main() {
	flag.Parse()

	if err := main1(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func main1() error {
	var zones []string
	switch {
	case oneZone != "":
		fmt.Fprintf(os.Stderr, "Querying single zone: %s\n", oneZone)
		zones = []string{oneZone}

	case quick:
		zones = strings.Fields(`com net org co io nr kr jp de in`)
		fmt.Fprintf(os.Stderr, "Quick mode enabled, operating on %d zones\n", len(zones))

	default:
		for _, z := range zonedb.Zones {
			zones = append(zones, z.Domain)
		}
	}

	prefixes, err := readLines("prefixes.txt")
	if err != nil {
		return err
	}

	domains := make(map[string]bool, len(zones)*len(prefixes))
	for _, zone := range zones {
		for _, prefix := range prefixes {
			domain := prefix + "." + zone
			domains[domain] = true
			host, err := whois.Server(domain)
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
			req, err := whois.NewRequest(domain)
			if err != nil {
				return
			}

			// Only re-fetch responses > 1 month old
			res, err := whois.ReadMIMEFile(whoistest.ResponseFilename(req.Query, req.Host))
			if err == nil && time.Since(res.FetchedAt) < maxAge {
				if v {
					fmt.Fprintf(os.Stderr, "Skipping %s from %s\n", req.Query, req.Host)
				}
				responses <- nil
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
			res, err = whois.DefaultClient.Fetch(req)
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

			fn := whoistest.ResponseFilename(res.Query, res.Host)

			dir := filepath.Dir(fn)
			err := os.MkdirAll(dir, os.ModePerm)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error creating response directory for %s: %s\n", res.Host, err)
				return
			}

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
