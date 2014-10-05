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
	"sort"
	"strings"

	"github.com/domainr/whois"
	"github.com/domainr/whoistest"
	"github.com/wsxiaoys/terminal/color"
)

var (
	keys = make(map[string]string)
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

	sorted := make([]string, 0, len(keys))
	for k, _ := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)

	for _, k := range sorted {
		color.Printf("@{|c}%- 40s  @{|.}%s\n", k, keys[k])
	}
	color.Printf("@{|w}%d unique keys found\n", len(keys))

	return nil
}

var (
	reEmptyLine   = regexp.MustCompile(`^\s*$`)
	reKey         = `([^,a-z\:\],][^\:\]]{0,39}\S|[a-z-]{3,40})`
	reBareKey     = regexp.MustCompile(`^\s*` + reKey + `\s*\:\s*$`)
	reKeyValue    = regexp.MustCompile(`^\s*` + reKey + `\s*\:\s*(.*\S)\s*$`)
	reAltKey      = regexp.MustCompile(`^\s*\[` + reKey + `\]\s*$`)
	reAltKeyValue = regexp.MustCompile(`^\s*\[` + reKey + `\]\s*(.*\S)\s*$`)
	reBareValue   = regexp.MustCompile(`^      \s+(.*\S)\s*$`)
	reNotice      = regexp.MustCompile(strings.Join([]string{
		`^%`,                // whois.de, whois.registro.br
		`^# `,               // whois.kr
		`^\[ .+ \]$`,        // whois.jprs.jp
		`^>>>.+<<<$`,        // Database last updated...
		`^[^\:]+https?\://`, // Line with an URL
		`^NOTE: |^NOTICE: |^TERMS OF USE: `,
	}, "|"))
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
		color.Printf("@{|.}% 4d  ", line)

		// Get next line
		text := s.Text()

		// Notices and empty lines
		if reEmptyLine.MatchString(text) {
			color.Printf("@{|w}EMPTY\n")
			continue
		}
		if m := reNotice.FindStringSubmatch(text); m != nil {
			color.Printf("@{|w}%- 16s  %s\n", "NOTICE", text)
			continue
		}

		// Keys and values
		if m := reAltKeyValue.FindStringSubmatch(text); m != nil {
			addKey(m[1], res.Host)
			color.Printf("@{|w}%- 16s  @{c}%- 40s @{w}%s\n", "ALT_KEY_VALUE", m[1], m[2])
			continue
		}
		if m := reAltKey.FindStringSubmatch(text); m != nil {
			addKey(m[1], res.Host)
			color.Printf("@{|w}%- 16s  @{c}%s\n", "BARE_ALT_KEY", m[1])
			continue
		}
		if m := reKeyValue.FindStringSubmatch(text); m != nil {
			addKey(m[1], res.Host)
			color.Printf("@{|w}%- 16s  @{c}%- 40s @{w}%s\n", "KEY_VALUE", m[1], m[2])
			continue
		}
		if m := reBareKey.FindStringSubmatch(text); m != nil {
			addKey(m[1], res.Host)
			color.Printf("@{|w}%- 16s  @{c}%s\n", "BARE_KEY", m[1])
			continue
		}
		if m := reBareValue.FindStringSubmatch(text); m != nil {
			color.Printf("@{|w}%- 16s  @{c}%- 40s @{w}%s\n", "BARE_VALUE", "", m[1])
			continue
		}

		// Unknown
		color.Printf("@{|.}%- 16s  @{|.}%s\n", "UNKNOWN", text)
	}

	fmt.Printf("\n")
}

func addKey(k, host string) string {
	k = transformKey(k)
	if _, ok := keys[k]; !ok {
		keys[k] = host
	} else if !strings.Contains(keys[k], host) {
		keys[k] = keys[k] + "  " + host
	}
	return k
}

var (
	reStrip = regexp.MustCompile(`[[:punct:]]`)
	reSpace = regexp.MustCompile(`\s+`)
)

func transformKey(k string) string {
	k = strings.ToUpper(k)
	k = reStrip.ReplaceAllLiteralString(k, " ")
	k = strings.TrimSpace(k)
	k = reSpace.ReplaceAllLiteralString(k, "_")
	return k
}
