package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type client struct {
	t   *testing.T
	ts  *httptest.Server
	key *ecdsa.PrivateKey
}

func newClient(t *testing.T, ts *httptest.Server) *client {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &client{t: t, ts: ts, key: k}
}

func (c *client) pub() string {
	raw := append([]byte{4}, c.key.X.FillBytes(make([]byte, 32))...)
	raw = append(raw, c.key.Y.FillBytes(make([]byte, 32))...)
	return base64.StdEncoding.EncodeToString(raw)
}

func (c *client) sign(body []byte) string {
	sum := sha256.Sum256(body)
	r, s, err := ecdsa.Sign(rand.Reader, c.key, sum[:])
	if err != nil {
		c.t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...))
}

func (c *client) nonce() string {
	resp, err := http.Post(c.ts.URL+"/v1/challenge", "application/json", strings.NewReader(`{"key":"`+c.pub()+`"}`))
	if err != nil || resp.StatusCode != 200 {
		c.t.Fatalf("challenge: %v %v", err, resp.Status)
	}
	var out struct{ Nonce string }
	json.NewDecoder(resp.Body).Decode(&out)
	return out.Nonce
}

const goodBody = `{"code":"0004000000055D00-C582E699CEBEDF79","addresses":["0010A7C8","0016D6B4","0030F030"]}`

func (c *client) pkg(nonce, body string) []byte {
	return []byte(fmt.Sprintf(`{"v":1,"kind":"zakuro-hints","key":"%s","nonce":"%s","created":%d,"launcher":"build 131, after version 0.0.7a","zakuro":"642579ff3","body":%s}`,
		c.pub(), nonce, time.Now().Unix(), body))
}

func (c *client) send(pkg []byte, sig string) int {
	req, _ := http.NewRequest("POST", c.ts.URL+"/v1/submit/zakuro-hints", bytes.NewReader(pkg))
	req.Header.Set("Content-Type", "application/vnd.nativemons.package+json")
	req.Header.Set("X-NM-Signature", sig)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	return resp.StatusCode
}

func setup(t *testing.T) (*httptest.Server, *store) {
	st, err := openStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(newServer(st, false).routes())
	t.Cleanup(ts.Close)
	return ts, st
}

func TestGoodPackageIsQueued(t *testing.T) {
	ts, st := setup(t)
	c := newClient(t, ts)
	p := c.pkg(c.nonce(), goodBody)
	if code := c.send(p, c.sign(p)); code != 202 {
		t.Fatalf("got %d", code)
	}
	q, _ := st.list("queue")
	if len(q) != 1 {
		t.Fatalf("queue has %d", len(q))
	}
	// The signature is kept beside the package, and still checks out against it.
	kept, err1 := os.ReadFile(filepath.Join(st.dir, "queue", q[0].Receipt+".package"))
	sig, err2 := os.ReadFile(filepath.Join(st.dir, "queue", q[0].Receipt+".sig"))
	key, _, err3 := parseKey(c.pub())
	if err1 != nil || err2 != nil || err3 != nil || !bytes.Equal(kept, p) || !verify(key, kept, string(sig)) {
		t.Fatal("the kept package and signature don't check out")
	}
}

func TestRefused(t *testing.T) {
	ts, st := setup(t)
	cases := map[string]func(c *client) ([]byte, string){
		"tampered after signing": func(c *client) ([]byte, string) {
			p := c.pkg(c.nonce(), goodBody)
			sig := c.sign(p)
			return bytes.Replace(p, []byte("0016D6B4"), []byte("0016D6B6"), 1), sig
		},
		"signed by another key": func(c *client) ([]byte, string) {
			p := c.pkg(c.nonce(), goodBody)
			return p, newClient(t, ts).sign(p)
		},
		"made-up challenge": func(c *client) ([]byte, string) {
			p := c.pkg(base64.StdEncoding.EncodeToString(make([]byte, 32)), goodBody)
			return p, c.sign(p)
		},
		"unknown field": func(c *client) ([]byte, string) {
			p := c.pkg(c.nonce(), `{"code":"0004000000055D00-C582E699CEBEDF79","addresses":["0010A7C8"],"x":1}`)
			return p, c.sign(p)
		},
		"duplicate field": func(c *client) ([]byte, string) {
			p := c.pkg(c.nonce(), `{"code":"0004000000055D00-C582E699CEBEDF79","addresses":["0010A7C8"],"addresses":["0010A7CA"]}`)
			return p, c.sign(p)
		},
		"title not built": func(c *client) ([]byte, string) {
			p := c.pkg(c.nonce(), `{"code":"0004000000030800-C582E699CEBEDF79","addresses":["0010A7C8"]}`)
			return p, c.sign(p)
		},
		"address out of range": func(c *client) ([]byte, string) {
			p := c.pkg(c.nonce(), `{"code":"0004000000055D00-C582E699CEBEDF79","addresses":["0000A7C8"]}`)
			return p, c.sign(p)
		},
		"not in rising order": func(c *client) ([]byte, string) {
			p := c.pkg(c.nonce(), `{"code":"0004000000055D00-C582E699CEBEDF79","addresses":["0016D6B4","0010A7C8"]}`)
			return p, c.sign(p)
		},
		"lowercase address": func(c *client) ([]byte, string) {
			p := c.pkg(c.nonce(), `{"code":"0004000000055D00-C582E699CEBEDF79","addresses":["0010a7c8"]}`)
			return p, c.sign(p)
		},
		"addresses null": func(c *client) ([]byte, string) {
			p := c.pkg(c.nonce(), `{"code":"0004000000055D00-C582E699CEBEDF79","addresses":null}`)
			return p, c.sign(p)
		},
		"data after the object": func(c *client) ([]byte, string) {
			p := append(c.pkg(c.nonce(), goodBody), []byte(` {}`)...)
			return p, c.sign(p)
		},
		"spaces in the layout": func(c *client) ([]byte, string) {
			p := bytes.Replace(c.pkg(c.nonce(), goodBody), []byte(`,"kind"`), []byte(`, "kind"`), 1)
			return p, c.sign(p)
		},
		"fields reordered": func(c *client) ([]byte, string) {
			p := c.pkg(c.nonce(), `{"addresses":["0010A7C8","0016D6B4","0030F030"],"code":"0004000000055D00-C582E699CEBEDF79"}`)
			return p, c.sign(p)
		},
		"an escaped character": func(c *client) ([]byte, string) {
			p := bytes.Replace(c.pkg(c.nonce(), goodBody), []byte(`"zakuro":"642579ff3"`), []byte("\"zakuro\":\"\x5cu003642579ff3\""), 1)
			return p, c.sign(p)
		},
		"a trailing newline": func(c *client) ([]byte, string) {
			p := append(c.pkg(c.nonce(), goodBody), '\n')
			return p, c.sign(p)
		},
		"script in a version string": func(c *client) ([]byte, string) {
			p := bytes.Replace(c.pkg(c.nonce(), goodBody), []byte(`build 131, after version 0.0.7a`), []byte(`<script>x</script>`), 1)
			return p, c.sign(p)
		},
	}
	for name, make := range cases {
		c := newClient(t, ts)
		p, sig := make(c)
		if code := c.send(p, sig); code == 202 {
			t.Errorf("%s: accepted", name)
		}
	}
	if q, _ := st.list("queue"); len(q) != 0 {
		t.Fatalf("%d refused packages reached the queue", len(q))
	}
}

func TestChallengeWorksOnce(t *testing.T) {
	ts, _ := setup(t)
	c := newClient(t, ts)
	p := c.pkg(c.nonce(), goodBody)
	sig := c.sign(p)
	if code := c.send(p, sig); code != 202 {
		t.Fatalf("first: %d", code)
	}
	if code := c.send(p, sig); code == 202 {
		t.Fatal("the same package was taken twice")
	}
}

func TestOtherKeysChallengeRefused(t *testing.T) {
	ts, _ := setup(t)
	a, b := newClient(t, ts), newClient(t, ts)
	p := b.pkg(a.nonce(), goodBody)
	if code := b.send(p, b.sign(p)); code == 202 {
		t.Fatal("a challenge given to one key worked for another")
	}
}

func TestBannedKeyRefused(t *testing.T) {
	ts, st := setup(t)
	c := newClient(t, ts)
	raw, _ := base64.StdEncoding.DecodeString(c.pub())
	st.ban(keyID(raw))
	resp, _ := http.Post(ts.URL+"/v1/challenge", "application/json", strings.NewReader(`{"key":"`+c.pub()+`"}`))
	if resp.StatusCode != 403 {
		t.Fatalf("got %d", resp.StatusCode)
	}
}

func TestTooLargeRefused(t *testing.T) {
	ts, _ := setup(t)
	c := newClient(t, ts)
	big := c.pkg(c.nonce(), `{"code":"0004000000055D00-C582E699CEBEDF79","addresses":["`+strings.Repeat("A", 1<<20)+`"]}`)
	if code := c.send(big, c.sign(big)); code != 413 {
		t.Fatalf("got %d", code)
	}
}

func TestPerKeyLimit(t *testing.T) {
	ts, _ := setup(t)
	c := newClient(t, ts)
	accepted := 0
	for i := 0; i < kinds["zakuro-hints"].perDay+3; i++ {
		p := c.pkg(c.nonce(), goodBody)
		if c.send(p, c.sign(p)) == 202 {
			accepted++
		}
	}
	if accepted != kinds["zakuro-hints"].perDay {
		t.Fatalf("accepted %d", accepted)
	}
}

func TestRequestShapeRefused(t *testing.T) {
	ts, st := setup(t)
	c := newClient(t, ts)
	send := func(url string, body []byte, chunked bool) int {
		var rd io.Reader = bytes.NewReader(body)
		if chunked {
			rd = io.MultiReader(bytes.NewReader(body)) // no length known: sent chunked
		}
		req, _ := http.NewRequest("POST", url, rd)
		req.Header.Set("Content-Type", "application/vnd.nativemons.package+json")
		req.Header.Set("X-NM-Signature", c.sign(body))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode
	}
	p := c.pkg(c.nonce(), goodBody)
	if code := send(ts.URL+"/v1/submit/zakuro-hints?x=1", p, false); code == 202 {
		t.Error("a query was accepted")
	}
	p = c.pkg(c.nonce(), goodBody)
	if code := send(ts.URL+"/v1/submit/zakuro-hints", p, true); code == 202 {
		t.Error("a chunked body was accepted")
	}
	if code := send(ts.URL+"/v1/submit/zakuro-hints", []byte(`{}`), false); code == 202 {
		t.Error("a tiny body was accepted")
	}
	resp, _ := http.Post(ts.URL+"/v1/challenge", "application/json", strings.NewReader(`{ "key":"`+c.pub()+`"}`))
	if resp.StatusCode == 200 {
		t.Error("a challenge request with a space was accepted")
	}
	if q, _ := st.list("queue"); len(q) != 0 {
		t.Fatalf("%d reached the queue", len(q))
	}
}
