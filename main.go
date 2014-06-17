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

	"code.google.com/p/go.net/idna"
	"github.com/domainr/go-whois/whois"
)

var (
	v, quick      bool
	concurrency   int
	zones         []string
	prefixes      []string
	_, FILE, _, _ = runtime.Caller(0)
	DIR           = filepath.Dir(FILE)
)

func init() {
	flag.BoolVar(&v, "v", false, "verbose output (to stderr)")
	flag.BoolVar(&quick, "quick", false, "Only work on a subset of zones")
	flag.IntVar(&concurrency, "concurrency", 8, "Set maximum number of concurrent requests")
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
		zones = []string{"com", "net", "org", "co", "io", "nr"}
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
				if _, ok := domains[hostParent]; !ok {
					fmt.Fprintf(os.Stderr, "  + %s\n", hostParent)
					domains[hostParent] = true
				}
			}
		}
	}

	fmt.Fprintf(os.Stderr, "Querying whois for %d domains (%d prefixes × %d zones + extras)\n", len(domains), len(prefixes), len(zones))

	responses := make(chan *whois.Response, len(domains))
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
	for i := 0; i < len(domains); i++ {
		select {
		case res := <-responses:
			if res == nil {
				continue
			}

			dir := filepath.Join(DIR, "data", "responses", res.Host)
			err = os.MkdirAll(dir, os.ModePerm)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error creating response directory for %s: %s\n", res.Host, err)
				continue
			}

			fn := filepath.Join(dir, (sha1hex(res.Body) + ".mime"))
			f, err := os.Create(fn)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error creating response file for %s: %s\n", res.Query, err)
				continue
			}
			res.WriteMIME(f)
			f.Close()
		}
	}
	return nil
}

var whitespaceAndComments = regexp.MustCompile(`\s+|#.+$`)

func readLines(fn string) ([]string, error) {
	fmt.Fprintf(os.Stderr, "Reading %s\n", fn)
	f, err := os.Open(filepath.Join(DIR, "data", fn))
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
