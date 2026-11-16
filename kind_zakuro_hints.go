package main

import (
	"bytes"
	"errors"
	"regexp"
	"strconv"
)

// The titles 3DSrecomp+Zakuro builds (Recomp.Titles in the launcher).
var zakuroTitles = map[string]bool{
	"0004000000055D00": true, "0004000000055E00": true, "000400000011C400": true, "000400000011C500": true,
	"0004000000164800": true, "0004000000175E00": true, "00040000001B5000": true, "00040000001B5100": true,
}

var (
	reCode = regexp.MustCompile(`^([0-9A-F]{16})-[0-9A-F]{16}$`)
	reAddr = regexp.MustCompile(`^[0-9A-F]{8}$`)
)

const maxHints = 65536

// A Zakuro hint list: {"code":"<title id>-<code hash>","addresses":["0010A7C8",...]}, addresses in
// rising order with no repeats, each inside a 3DS title's code (0x00100000 up to 0x10000000).
func checkZakuroHints(body []byte) (string, []byte, error) {
	var code string
	var addrs []string
	if err := parseStrict(body, map[string]any{"code": &code, "addresses": &addrs}); err != nil {
		return "", nil, err
	}
	m := reCode.FindStringSubmatch(code)
	if m == nil || !zakuroTitles[m[1]] {
		return "", nil, errors.New("not a title nativeMons builds")
	}
	if len(addrs) == 0 || len(addrs) > maxHints {
		return "", nil, errors.New("bad number of addresses")
	}
	var last uint64
	for i, a := range addrs {
		if !reAddr.MatchString(a) {
			return "", nil, errors.New("bad address")
		}
		v, _ := strconv.ParseUint(a, 16, 32)
		if v < 0x00100000 || v >= 0x10000000 {
			return "", nil, errors.New("address outside a title's code")
		}
		if i > 0 && v <= last {
			return "", nil, errors.New("addresses not in rising order")
		}
		last = v
	}
	var c bytes.Buffer
	c.WriteString(`{"code":"` + code + `","addresses":[`)
	for i, a := range addrs {
		if i > 0 {
			c.WriteByte(',')
		}
		c.WriteString(`"` + a + `"`)
	}
	c.WriteString(`]}`)
	return code + ", " + strconv.Itoa(len(addrs)) + " addresses", c.Bytes(), nil
}
