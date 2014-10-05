// +build ignore

// Enumerate unique keys from key/values found in the whois responses.
// To use: go run enumerate.go

package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"regexp"

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
		scan(res)
	}
	return nil
}

var (
	reEmptyLine     = regexp.MustCompile(`^\s*$`)
	reKey           = regexp.MustCompile(`^\s*([^\:]*\S)\s*\:\s*$`)
	reKeyValue      = regexp.MustCompile(`^\s*([^\:]*\S)\s*\:\s*(.*\S)\s*$`)
	reAltKey        = regexp.MustCompile(`^\s*\[([^\]]+)\]\s*$`)
	reAltKeyValue   = regexp.MustCompile(`^\s*\[([^\]]+)\]\s*(.*\S)\s*$`)
	reIndentedValue = regexp.MustCompile(`^      \s+(.*\S)\s*$`)
	deNotice        = `^% .*$`
	jpNotice        = `^\[ .+ \]$`
	krNotice        = `^# .*$`
	updated         = `^<<<.+>>>$`
	reNotice        = regexp.MustCompile(
		deNotice + "|" + jpNotice + "|" + krNotice + "|" + updated)
)

func scan(res *whois.Response) {
	r, err := res.Reader()
	if err != nil {
		return
	}
	line := 0
	s := bufio.NewScanner(r)
	for s.Scan() {
		line++
		text := s.Text()

		if reEmptyLine.MatchString(text) {
			fmt.Printf("% 4d  EMPTY\n", line)
			continue
		}

		if m := reNotice.FindStringSubmatch(text); m != nil {
			fmt.Printf("% 4d  %- 20s  %s\n", line, "NOTICE", m[0])
			continue
		}

		if m := reAltKeyValue.FindStringSubmatch(text); m != nil {
			fmt.Printf("% 4d  %- 20s  %- 40s %s\n", line, "ALT_KEY_VALUE", m[1], m[2])
			continue
		}

		if m := reAltKey.FindStringSubmatch(text); m != nil {
			fmt.Printf("% 4d  %- 20s  %s\n", line, "ALT_KEY", m[1])
			continue
		}

		if m := reKeyValue.FindStringSubmatch(text); m != nil {
			fmt.Printf("% 4d  %- 20s  %- 40s %s\n", line, "KEY_VALUE", m[1], m[2])
			continue
		}

		if m := reKey.FindStringSubmatch(text); m != nil {
			fmt.Printf("% 4d  %- 20s  %s\n", line, "KEY", m[1])
			continue
		}

		if m := reIndentedValue.FindStringSubmatch(text); m != nil {
			fmt.Printf("% 4d  %- 20s  %- 40s %s\n", line, "INDENTED_VALUE", "", m[1])
			continue
		}

		fmt.Fprintf(os.Stderr, "% 4d  %- 20s  %s\n", line, "UNKNOWN", text)
	}
	fmt.Printf("\n")
}
