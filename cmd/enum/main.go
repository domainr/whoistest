// This command enumerates unique keys/values found in testdata/responses.
// To use: go run cmd/enum/main.go

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

func main() {
	flag.Parse()
	if err := main1(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func main1() error {
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	wd = wd + "/"

	fns, err := whoistest.ResponseFiles()
	if err != nil {
		return err
	}

	for _, fn := range fns {
		res, err := whois.ReadMIMEFile(fn)
		if err != nil {
			color.Fprintf(os.Stderr, "@{|r}Error reading response file %s: %s\n", fn, err)
			continue
		}
		if res.MediaType != "text/plain" {
			continue
		}
		scan(res, strings.TrimPrefix(fn, wd))
	}

	logKeys()

	return nil
}

var (
	reEmptyLine = regexp.MustCompile(`^\s*$`)

	reKey         = `([^,a-z\:\],][^\:\]]{0,39}\S|[a-z-]{3,40})`
	reBareKey     = regexp.MustCompile(`^[ \t]{0,3}` + reKey + `\s*\:\s*$`)
	reKeyValue    = regexp.MustCompile(`^[ \t]{0,3}` + reKey + `\s*\:\s*(.*\S)\s*$`)
	reAltKey      = regexp.MustCompile(`^\[` + reKey + `\]\s*$`)
	reAltKeyValue = regexp.MustCompile(`^\[` + reKey + `\]\s*(.*\S)\s*$`)
	reBareValue   = regexp.MustCompile(`^      \s+(.*\S)\s*$`)

	reUnavailable = regexp.MustCompile(strings.Join([]string{
		`^Above domain name is not available for registration\.$`,
	}, "|"))

	reReserved = regexp.MustCompile(strings.Join([]string{
		`^Domain reserved$`,
	}, "|"))

	reNotFound = regexp.MustCompile(strings.Join([]string{
		`^No match\!\!$`,
		`^NOT FOUND$`,
		`^no matching record.$`,
		`^Not found\: .+$`,
		`^No match for "([^"]+)"\.$`,
		`^% No match for domain "([^"]+)"$`,
		`^% No entries found for query "([^"]+)"\.$`,
		`^Domain (\S+) is available for purchase$`,
		`^%% No entries found in the .+ Database\.$`,
		`^Above domain name is not registered to [^\.]+\.$`,
	}, "|"))

	reNotice = regexp.MustCompile(strings.Join([]string{
		`^%`,                // whois.de, whois.registro.br
		`^# `,               // whois.kr
		`^\[ .+ \]$`,        // whois.jprs.jp
		`^>>>.+<<<$`,        // Database last updated...
		`^[^\:]+https?\://`, // Line with an URL
		`^NOTE: |^NOTICE: |^TERMS OF USE: `,
	}, "|"))
)

func scan(res *whois.Response, fn string) {
	color.Printf("@{|g}%s\n", fn)

	r, err := res.Reader()
	if err != nil {
		return
	}

	off := len(res.Header())
	line := 0
	s := bufio.NewScanner(r)
	for s.Scan() {
		line++
		color.Printf("@{|.}% 4d  ", line)

		// Get next line
		text := s.Text()

		// Empty lines
		if reEmptyLine.MatchString(text) {
			color.Printf("@{|w}EMPTY\n")
			continue
		}

		// Status messages
		if m := reNotFound.FindStringSubmatch(text); m != nil {
			color.Printf("@{|y}%- 16s  %s\n", "NOT_FOUND", text)
			continue
		}
		if m := reUnavailable.FindStringSubmatch(text); m != nil {
			color.Printf("@{|y}%- 16s  %s\n", "UNAVAILABLE", text)
			continue
		}
		if m := reReserved.FindStringSubmatch(text); m != nil {
			color.Printf("@{|y}%- 16s  %s\n", "UNAVAILABLE", text)
			continue
		}

		// Notices
		if m := reNotice.FindStringSubmatch(text); m != nil {
			color.Printf("@{|w}%- 16s  %s\n", "NOTICE", text)
			continue
		}

		// Keys and values
		if m := reAltKeyValue.FindStringSubmatch(text); m != nil && known(m[1], fn, line+off) {
			color.Printf("@{|w}%- 16s  @{c}%- 40s @{w}%s\n", "ALT_KEY_VALUE", m[1], m[2])
			continue
		}
		if m := reAltKey.FindStringSubmatch(text); m != nil && known(m[1], fn, line+off) {
			color.Printf("@{|w}%- 16s  @{c}%s\n", "BARE_ALT_KEY", m[1])
			continue
		}
		if m := reKeyValue.FindStringSubmatch(text); m != nil && known(m[1], fn, line+off) {
			color.Printf("@{|w}%- 16s  @{c}%- 40s @{w}%s\n", "KEY_VALUE", m[1], m[2])
			continue
		}
		if m := reBareKey.FindStringSubmatch(text); m != nil && known(m[1], fn, line+off) {
			color.Printf("@{|w}%- 16s  @{c}%s\n", "BARE_KEY", m[1])
			continue
		}
		if m := reBareValue.FindStringSubmatch(text); m != nil {
			color.Printf("@{|w}%- 16s  @{c}%- 40s @{w}%s\n", "BARE_VALUE", "", m[1])
			continue
		}

		// Text (unknown)
		color.Printf("@{|.}%- 16s  @{|.}%s\n", "TEXT", text)
	}

	fmt.Printf("\n")
}

func known(k, fn string, line int) bool {
	_, ok := knownKeys[transformKey(k)]
	if !ok {
		addKey(k, fn, line)
	}
	return ok
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

var (
	keys = make(map[string]string)
)

func addKey(k, fn string, line int) {
	keys[k] = fmt.Sprintf("%s:%d", fn, line)
}

func logKeys() {
	sorted := make([]string, 0, len(keys))
	for k, _ := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	for _, k := range sorted {
		color.Printf("@{|.}%- 80s @{|c}%s  \n", keys[k], strings.TrimSpace(k))
	}
	color.Printf("@{|w}%d potential new keys\n", len(keys))
}

var knownKeys = map[string]bool{
	"AC_E_MAIL":                               true,
	"AC_PHONE_NUMBER":                         true,
	"ADDRESS":                                 true,
	"ADMINISTRATIVE_CONTACT_AC":               true,
	"ADMINISTRATIVE_CONTACT_ADDRESS1":         true,
	"ADMINISTRATIVE_CONTACT_CITY":             true,
	"ADMINISTRATIVE_CONTACT_COUNTRY":          true,
	"ADMINISTRATIVE_CONTACT_COUNTRY_CODE":     true,
	"ADMINISTRATIVE_CONTACT_EMAIL":            true,
	"ADMINISTRATIVE_CONTACT_FACSIMILE_NUMBER": true,
	"ADMINISTRATIVE_CONTACT_ID":               true,
	"ADMINISTRATIVE_CONTACT_NAME":             true,
	"ADMINISTRATIVE_CONTACT_ORGANIZATION":     true,
	"ADMINISTRATIVE_CONTACT_PHONE_NUMBER":     true,
	"ADMINISTRATIVE_CONTACT_POSTAL_CODE":      true,
	"ADMINISTRATIVE_CONTACT_STATE_PROVINCE":   true,
	"ADMIN_C":                             true,
	"ADMIN_CITY":                          true,
	"ADMIN_COUNTRY":                       true,
	"ADMIN_EMAIL":                         true,
	"ADMIN_FAX":                           true,
	"ADMIN_FAX_EXT":                       true,
	"ADMIN_ID":                            true,
	"ADMIN_NAME":                          true,
	"ADMIN_ORGANIZATION":                  true,
	"ADMIN_PHONE":                         true,
	"ADMIN_PHONE_EXT":                     true,
	"ADMIN_POSTAL_CODE":                   true,
	"ADMIN_STATE_PROVINCE":                true,
	"ADMIN_STREET":                        true,
	"ADMIN_STREET1":                       true,
	"ADMIN_STREET2":                       true,
	"ADMIN_STREET3":                       true,
	"ALGORITHM_1":                         true,
	"ALGORITHM_2":                         true,
	"ANNIVERSARY":                         true,
	"ANONYMOUS":                           true,
	"AUTHORIZED_AGENCY":                   true,
	"BILLING_C":                           true,
	"BILLING_CONTACT_ADDRESS1":            true,
	"BILLING_CONTACT_ADDRESS2":            true,
	"BILLING_CONTACT_CITY":                true,
	"BILLING_CONTACT_COUNTRY":             true,
	"BILLING_CONTACT_COUNTRY_CODE":        true,
	"BILLING_CONTACT_EMAIL":               true,
	"BILLING_CONTACT_FACSIMILE_NUMBER":    true,
	"BILLING_CONTACT_ID":                  true,
	"BILLING_CONTACT_NAME":                true,
	"BILLING_CONTACT_ORGANIZATION":        true,
	"BILLING_CONTACT_PHONE_NUMBER":        true,
	"BILLING_CONTACT_POSTAL_CODE":         true,
	"BILLING_CONTACT_STATE_PROVINCE":      true,
	"CHANGED":                             true,
	"CITY":                                true,
	"CONTACT":                             true,
	"CONTACT_INFORMATION":                 true,
	"COUNTRY":                             true,
	"COUNTRYCODE":                         true,
	"CREATED":                             true,
	"CREATED_BY_REGISTRAR":                true,
	"CREATED_ON":                          true,
	"CREATION_DATE":                       true,
	"DESCR":                               true,
	"DIGEST_1":                            true,
	"DIGEST_2":                            true,
	"DIGEST_TYPE_1":                       true,
	"DIGEST_TYPE_2":                       true,
	"DNSKEY":                              true,
	"DNSSEC":                              true,
	"DOMAIN":                              true,
	"DOMAIN_EXPIRATION_DATE":              true,
	"DOMAIN_ID":                           true,
	"DOMAIN_INFORMATION":                  true,
	"DOMAIN_LAST_UPDATED_DATE":            true,
	"DOMAIN_NAME":                         true,
	"DOMAIN_REGISTRATION_DATE":            true,
	"DOMAIN_STATUS":                       true,
	"DSLASTOK":                            true,
	"DSRECORD":                            true,
	"DSSTATUS":                            true,
	"DS_CREATED_1":                        true,
	"DS_CREATED_2":                        true,
	"DS_KEY_TAG_1":                        true,
	"DS_KEY_TAG_2":                        true,
	"DS_MAXIMUM_SIGNATURE_LIFE_1":         true,
	"DS_MAXIMUM_SIGNATURE_LIFE_2":         true,
	"DS_RDATA":                            true,
	"ELIGDATE":                            true,
	"ELIGSOURCE":                          true,
	"ELIGSTATUS":                          true,
	"EMAIL":                               true,
	"EXPIRATION_DATE":                     true,
	"EXPIRES":                             true,
	"EXPIRY":                              true,
	"E_MAIL":                              true,
	"FAX":                                 true,
	"FAX_NO":                              true,
	"FAX番号":                               true,
	"FLAGS":                               true,
	"HOLD":                                true,
	"HOLDER_C":                            true,
	"HOST_NAME":                           true,
	"IP_ADDRESS":                          true,
	"IP_주소":                               true,
	"KEYS":                                true,
	"KEYTAG":                              true,
	"LANGUAGE":                            true,
	"LAST_TRANSFERRED_DATE":               true,
	"LAST_UPDATE":                         true,
	"LAST_UPDATED_BY_REGISTRAR":           true,
	"LAST_UPDATED_DATE":                   true,
	"LAST_UPDATED_ON":                     true,
	"NAME":                                true,
	"NAMESERVERS":                         true,
	"NAME_SERVER":                         true,
	"NIC_HDL":                             true,
	"NIC_HDL_BR":                          true,
	"NOTIFY":                              true,
	"NOT_FOUND":                           true,
	"NSERVER":                             true,
	"NSLASTAA":                            true,
	"NSL_ID":                              true,
	"NSSTAT":                              true,
	"NS_1":                                true,
	"NS_2":                                true,
	"NS_3":                                true,
	"NS_4":                                true,
	"NS_5":                                true,
	"NS_LIST":                             true,
	"OBSOLETED":                           true,
	"ORGANISATION":                        true,
	"OWNER":                               true,
	"OWNERID":                             true,
	"OWNER_C":                             true,
	"PERSON":                              true,
	"PHONE":                               true,
	"POSTALCODE":                          true,
	"POSTAL_ADDRESS":                      true,
	"PUBLISHES":                           true,
	"QUERY":                               true,
	"REACHDATE":                           true,
	"REACHMEDIA":                          true,
	"REACHSOURCE":                         true,
	"REACHSTATUS":                         true,
	"REFERRAL_URL":                        true,
	"REGISTERED":                          true,
	"REGISTERED_DATE":                     true,
	"REGISTRANT":                          true,
	"REGISTRANT_ADDRESS":                  true,
	"REGISTRANT_ADDRESS1":                 true,
	"REGISTRANT_CITY":                     true,
	"REGISTRANT_CONTACT_EMAIL":            true,
	"REGISTRANT_COUNTRY":                  true,
	"REGISTRANT_COUNTRY_CODE":             true,
	"REGISTRANT_EMAIL":                    true,
	"REGISTRANT_FACSIMILE_NUMBER":         true,
	"REGISTRANT_FAX":                      true,
	"REGISTRANT_FAX_EXT":                  true,
	"REGISTRANT_ID":                       true,
	"REGISTRANT_NAME":                     true,
	"REGISTRANT_ORGANIZATION":             true,
	"REGISTRANT_PHONE":                    true,
	"REGISTRANT_PHONE_EXT":                true,
	"REGISTRANT_PHONE_NUMBER":             true,
	"REGISTRANT_POSTAL_CODE":              true,
	"REGISTRANT_STATE_PROVINCE":           true,
	"REGISTRANT_STREET":                   true,
	"REGISTRANT_STREET1":                  true,
	"REGISTRANT_STREET2":                  true,
	"REGISTRANT_STREET3":                  true,
	"REGISTRANT_ZIP_CODE":                 true,
	"REGISTRAR":                           true,
	"REGISTRAR_TECHNICAL_CONTACTS":        true,
	"REGISTRAR_URL_REGISTRATION_SERVICES": true,
	"REGISTRATION_DATE":                   true,
	"REGISTRY_EXPIRY_DATE":                true,
	"REMARKS":                             true,
	"RESPONSIBLE":                         true,
	"ROID":                                true,
	"ROLE":                                true,
	"RRC":                                 true,
	"SERVER_NAME":                         true,
	"SIGNING_KEY":                         true,
	"SOURCE":                              true,
	"SPONSORING_REGISTRAR":                true,
	"SPONSORING_REGISTRAR_IANA_ID":        true,
	"STATUS":                              true,
	"TECHNICAL_CONTACT_ADDRESS1":          true,
	"TECHNICAL_CONTACT_CITY":              true,
	"TECHNICAL_CONTACT_COUNTRY":           true,
	"TECHNICAL_CONTACT_COUNTRY_CODE":      true,
	"TECHNICAL_CONTACT_EMAIL":             true,
	"TECHNICAL_CONTACT_FACSIMILE_NUMBER":  true,
	"TECHNICAL_CONTACT_ID":                true,
	"TECHNICAL_CONTACT_NAME":              true,
	"TECHNICAL_CONTACT_ORGANIZATION":      true,
	"TECHNICAL_CONTACT_PHONE_NUMBER":      true,
	"TECHNICAL_CONTACT_POSTAL_CODE":       true,
	"TECHNICAL_CONTACT_STATE_PROVINCE":    true,
	"TECH_C":              true,
	"TECH_CITY":           true,
	"TECH_COUNTRY":        true,
	"TECH_EMAIL":          true,
	"TECH_FAX":            true,
	"TECH_FAX_EXT":        true,
	"TECH_ID":             true,
	"TECH_NAME":           true,
	"TECH_ORGANIZATION":   true,
	"TECH_PHONE":          true,
	"TECH_PHONE_EXT":      true,
	"TECH_POSTAL_CODE":    true,
	"TECH_STATE_PROVINCE": true,
	"TECH_STREET":         true,
	"TECH_STREET1":        true,
	"TECH_STREET2":        true,
	"TECH_STREET3":        true,
	"TROUBLE":             true,
	"TYPE":                true,
	"UPDATED_DATE":        true,
	"VARIANT":             true,
	"WEBSITE":             true,
	"WEB_PAGE":            true,
	"WHOIS":               true,
	"WHOIS_SERVER":        true,
	"ZONE_C":              true,
	"住所":                  true,
	"参考":                  true,
	"名前":                  true,
	"最終更新":                true,
	"有効期限":                true,
	"状態":                  true,
	"登録年月日":               true,
	"登録者名":                true,
	"郵便番号":                true,
	"電話番号":                true,
	"도메인이름":               true,
	"등록대행자":               true,
	"등록인":                 true,
	"등록인_우편번호":            true,
	"등록인_주소":              true,
	"등록일":                 true,
	"사용_종료일":              true,
	"정보공개여부":              true,
	"책임자":                 true,
	"책임자_전자우편":            true,
	"책임자_전화번호":            true,
	"최근_정보_변경일":           true,
	"호스트이름":               true,
}
