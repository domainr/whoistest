// +build ignore

// Enumerate unique keys from key/values found in the whois responses.
// To use: go run enumerate.go

package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"

	"github.com/domainr/whois"
	"github.com/domainr/whoistest"
)

func main() {
	flag.Parse()
	if err := main1(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func main1() error {
	fns, err := whoistest.ResponseFiles()
	if err != nil {
		return err
	}
	for _, fn := range fns {
		res, err := whois.ReadMIMEFile(fn)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading response file %s: %s\n", fn, err)
			continue
		}
		if res.MediaType != "text/plain" {
			continue
		}

		fmt.Printf("File:  %s\n", fn)
		fmt.Printf("Query: %s\n", res.Query)
		fmt.Printf("Host:  %s\n", res.Host)
		fmt.Printf("\n")
		scan(res)
		fmt.Printf("\n\n\n")
	}
	return nil
}

func scan(res *whois.Response) {
	r, err := res.Reader()
	if err != nil {
		return
	}
	line := 0
	s := bufio.NewScanner(r)
	for s.Scan() {
		line++
		fmt.Printf("% 4d %s\n", line, s.Text())
	}
}
