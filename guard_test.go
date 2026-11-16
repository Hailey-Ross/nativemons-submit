package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// post sends a body to a path with a content type and returns the status and the answer.
func post(t *testing.T, url, ctype string, body []byte) (int, string) {
	resp, err := http.Post(url, ctype, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(out)
}

func (c *client) challengeStatus() (int, string) {
	return post(c.t, c.ts.URL+"/v1/challenge", "application/json", []byte(`{"key":"`+c.pub()+`"}`))
}

const badBody = `{"code":"0004000000055D00-C582E699CEBEDF79","addresses":["0016D6B4","0010A7C8"]}` // not in order

func TestAddressBlockedAfterStrikes(t *testing.T) {
	ts, st, _ := setupWith(t, nil)
	for i := 0; i < ipStrikeLimit; i++ {
		if code, _ := post(t, ts.URL+"/v1/submit/nope", "application/vnd.nativemons.package+json", []byte(`{}`)); code != 404 {
			t.Fatalf("strike %d: got %d", i+1, code)
		}
	}
	// Blocked now, even for a request that's fine, and turned away before it's read.
	c := newClient(t, ts)
	if code, body := c.challengeStatus(); code != 429 || !strings.Contains(body, "blocked") {
		t.Fatalf("after %d strikes: %d %s", ipStrikeLimit, code, body)
	}
	if code, _ := post(t, ts.URL+"/v1/submit/zakuro-hints", "text/plain", []byte(`x`)); code != 429 {
		t.Fatalf("blocked submit: %d", code)
	}
	// Every refusal and the block are kept; the turned-away requests aren't.
	rs := st.refusals(time.Now().Add(-time.Hour))
	if len(rs) != ipStrikeLimit+1 || rs[len(rs)-1].Reason != "address blocked" {
		t.Fatalf("refusals.log has %d, last %+v", len(rs), rs[len(rs)-1])
	}
}

func TestBlockEnds(t *testing.T) {
	var mu sync.Mutex
	now := time.Now()
	ts, _, _ := setupWith(t, func(s *server) {
		s.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	})
	for i := 0; i < ipStrikeLimit; i++ {
		post(t, ts.URL+"/v1/submit/nope", "application/vnd.nativemons.package+json", []byte(`{}`))
	}
	c := newClient(t, ts)
	if code, _ := c.challengeStatus(); code != 429 {
		t.Fatalf("not blocked: %d", code)
	}
	mu.Lock()
	now = now.Add(blockFor + time.Minute)
	mu.Unlock()
	if code, _ := c.challengeStatus(); code != 200 {
		t.Fatalf("still blocked after the block ended: %d", code)
	}
}

func TestJunkDoesNotUseTheAllowance(t *testing.T) {
	ts, _, _ := setupWith(t, func(s *server) { s.ipStrikes = 1000 })
	junk := bytes.Repeat([]byte("x"), 400)
	for i := 0; i < uploadsPerIP+10; i++ {
		post(t, ts.URL+"/v1/submit/zakuro-hints", "text/plain", junk)
		post(t, ts.URL+"/v1/submit/nope", "application/vnd.nativemons.package+json", junk)
	}
	c := newClient(t, ts)
	p := c.pkg(c.nonce(), goodBody)
	if code := c.send(p, c.sign(p)); code != 202 {
		t.Fatalf("a good package after junk: %d", code)
	}
}

func TestInstallBlockedAfterStrikes(t *testing.T) {
	ts, st, _ := setupWith(t, func(s *server) { s.ipStrikes = 1000 })
	c := newClient(t, ts)
	for i := 0; i < keyStrikeLimit; i++ {
		p := c.pkg(c.nonce(), badBody)
		if code := c.send(p, c.sign(p)); code != 400 {
			t.Fatalf("strike %d: got %d", i+1, code)
		}
	}
	if code, body := c.challengeStatus(); code != 429 || !strings.Contains(body, "blocked") {
		t.Fatalf("install not blocked: %d %s", code, body)
	}
	// Another install at the same address is untouched.
	other := newClient(t, ts)
	p := other.pkg(other.nonce(), goodBody)
	if code := other.send(p, other.sign(p)); code != 202 {
		t.Fatalf("another install: %d", code)
	}
	raw, _ := base64.StdEncoding.DecodeString(c.pub())
	found := false
	for _, r := range st.refusals(time.Now().Add(-time.Hour)) {
		if r.Reason == "install blocked" && r.Key == keyID(raw) {
			found = true
		}
	}
	if !found {
		t.Fatal("the block isn't in refusals.log")
	}
}

// Anyone can send someone else's public key, so a refusal before the signature holds never counts against it.
func TestUnprovenKeyNotStruck(t *testing.T) {
	ts, _, _ := setupWith(t, func(s *server) { s.ipStrikes = 1000 })
	victim, attacker := newClient(t, ts), newClient(t, ts)
	for i := 0; i < keyStrikeLimit*2; i++ {
		p := victim.pkg(victim.nonce(), badBody)
		if code := victim.send(p, attacker.sign(p)); code != 401 {
			t.Fatalf("forged %d: got %d", i+1, code)
		}
	}
	p := victim.pkg(victim.nonce(), goodBody)
	if code := victim.send(p, victim.sign(p)); code != 202 {
		t.Fatalf("the real install was blocked by forgeries: %d", code)
	}
}

func TestRefusalLogRollsOver(t *testing.T) {
	st, err := openStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	line := append(bytes.Repeat([]byte("x"), 1<<20), '\n')
	for i := 0; i < 12; i++ {
		if err := st.logRefusal(line); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"refusals.log", "refusals.log.1"} {
		data, err := os.ReadFile(filepath.Join(st.dir, name))
		if err != nil || len(data) > refusalLogMax {
			t.Fatalf("%s: %d bytes, %v", name, len(data), err)
		}
	}
}

func TestBlocksAndTagsSurviveRestart(t *testing.T) {
	st, err := openStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	first := newServer(st, false)
	tag := first.ipTag("203.0.113.7")
	for i := 0; i < ipStrikeLimit; i++ {
		first.strike("ip:"+tag, first.ipStrikes, ipStrikeWindow)
	}
	first.strike("key:"+strings.Repeat("ab", 16), 1, keyStrikeWindow)
	again := newServer(st, false) // a restart: the same data folder, a fresh process
	if again.ipTag("203.0.113.7") != tag {
		t.Fatal("the address tag changed across a restart")
	}
	if !again.blockedNow("ip:"+tag) || !again.blockedNow("key:"+strings.Repeat("ab", 16)) {
		t.Fatal("a block didn't survive a restart")
	}
	// Lifted by hand, it's gone at the next start.
	if found, err := st.unblock(tag); !found || err != nil {
		t.Fatalf("unblock: %v %v", found, err)
	}
	if newServer(st, false).blockedNow("ip:" + tag) {
		t.Fatal("still blocked after unblock and a restart")
	}
	if _, err := st.unblock("../etc/passwd"); err == nil {
		t.Fatal("unblock took something that isn't a tag or key id")
	}
}

func TestEndedBlocksAreDroppedAtStart(t *testing.T) {
	st, err := openStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-blockFor - time.Hour)
	old := newServer(st, false)
	old.now = func() time.Time { return past }
	old.strike("key:"+strings.Repeat("cd", 16), 1, keyStrikeWindow)
	if newServer(st, false).blockedNow("key:" + strings.Repeat("cd", 16)) {
		t.Fatal("a block that ended came back")
	}
}

// A player's wrong clock is answered, but never struck: the launcher can take the time from the challenge.
func TestWrongClockIsNotAStrike(t *testing.T) {
	ts, _, _ := setupWith(t, nil)
	c := newClient(t, ts)
	for i := 0; i < keyStrikeLimit*2; i++ {
		ahead := []byte(`"created":` + strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10)) // a clock an hour fast
		p := regexp.MustCompile(`"created":[0-9]+`).ReplaceAll(c.pkg(c.nonce(), goodBody), ahead)
		if code := c.send(p, c.sign(p)); code != 400 {
			t.Fatalf("wrong clock %d: got %d", i+1, code)
		}
	}
	code, body := c.challengeStatus()
	if code != 200 {
		t.Fatalf("blocked over its clock: %d %s", code, body)
	}
	var ch struct {
		Nonce        string
		Now, Expires int64
	}
	json.Unmarshal([]byte(body), &ch)
	if d := time.Now().Unix() - ch.Now; d < -5 || d > 5 || ch.Expires-ch.Now != int64(challengeLife/time.Second) {
		t.Fatalf("the challenge's now/expires are off: %+v", ch)
	}
	p := c.pkg(ch.Nonce, goodBody)
	if code := c.send(p, c.sign(p)); code != 202 {
		t.Fatalf("a good package after clock refusals: %d", code)
	}
}
