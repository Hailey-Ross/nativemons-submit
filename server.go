package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	challengeLife   = 5 * time.Minute
	challengesPerIP = 30 // an hour
	uploadsPerIP    = 60 // a day
	clockSlack      = 10 * time.Minute
	challengeBytes  = 512
)

type challenge struct {
	key     string // the key id it was given to
	expires time.Time
}

type server struct {
	store      *store
	trustProxy bool
	ipSalt     []byte
	now        func() time.Time

	mu         sync.Mutex
	challenges map[string]challenge   // nonce -> who and until when
	counts     map[string][]time.Time // "c:"/"u:"/"k:<kind>:" + who -> recent times
}

func newServer(st *store, trustProxy bool) *server {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		log.Fatal(err)
	}
	return &server{store: st, trustProxy: trustProxy, ipSalt: salt, now: time.Now,
		challenges: map[string]challenge{}, counts: map[string][]time.Time{}}
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/challenge", s.handleChallenge)
	mux.HandleFunc("POST /v1/submit/{kind}", s.handleSubmit)
	mux.HandleFunc("GET /v1/health", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok\n")) })
	return mux
}

// The client's address: the proxy's header only when told to trust it and the request came from this machine.
func (s *server) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if s.trustProxy && (host == "127.0.0.1" || host == "::1") {
		if f := r.Header.Get("X-Forwarded-For"); f != "" {
			parts := strings.Split(f, ",")
			if ip := net.ParseIP(strings.TrimSpace(parts[len(parts)-1])); ip != nil {
				return ip.String()
			}
		}
	}
	return host
}

// Addresses are kept only as a salted hash that changes with every restart.
func (s *server) ipTag(ip string) string {
	m := hmac.New(sha256.New, s.ipSalt)
	m.Write([]byte(ip))
	return hex.EncodeToString(m.Sum(nil)[:12])
}

// allow counts one more use against a limit over a window; false once the limit is reached.
func (s *server) allow(name string, limit int, window time.Duration) bool {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.counts[name][:0]
	for _, t := range s.counts[name] {
		if now.Sub(t) < window {
			kept = append(kept, t)
		}
	}
	if len(kept) >= limit {
		s.counts[name] = kept
		return false
	}
	s.counts[name] = append(kept, now)
	return true
}

func refuse(w http.ResponseWriter, status int, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": reason})
}

// POST /v1/challenge {"key": "<base64 P-256 point>"} -> {"nonce": "...", "expires": <unix>}
func (s *server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	ip := s.ipTag(s.clientIP(r))
	if !s.allow("c:"+ip, challengesPerIP, time.Hour) {
		refuse(w, http.StatusTooManyRequests, "too many requests")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, challengeBytes))
	if err != nil {
		refuse(w, http.StatusRequestEntityTooLarge, "too large")
		return
	}
	var keyB64 string
	if r.URL.RawQuery != "" || len(r.TransferEncoding) > 0 || parseStrict(body, map[string]any{"key": &keyB64}) != nil ||
		!reB64Key.MatchString(keyB64) || string(body) != `{"key":"`+keyB64+`"}` {
		refuse(w, http.StatusBadRequest, "bad request")
		return
	}
	_, raw, err := parseKey(keyB64)
	if err != nil {
		refuse(w, http.StatusBadRequest, "bad key")
		return
	}
	id := keyID(raw)
	if s.store.banned(id) {
		refuse(w, http.StatusForbidden, "not accepted")
		return
	}
	n := make([]byte, 32)
	if _, err := rand.Read(n); err != nil {
		refuse(w, http.StatusInternalServerError, "try again")
		return
	}
	nonce := base64.StdEncoding.EncodeToString(n)
	expires := s.now().Add(challengeLife)
	s.mu.Lock()
	for k, c := range s.challenges {
		if s.now().After(c.expires) {
			delete(s.challenges, k)
		}
	}
	s.challenges[nonce] = challenge{key: id, expires: expires}
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"nonce": nonce, "expires": expires.Unix()})
}

// POST /v1/submit/{kind}, the package as the body and its signature in X-NM-Signature.
func (s *server) handleSubmit(w http.ResponseWriter, r *http.Request) {
	ip := s.ipTag(s.clientIP(r))
	k, ok := kinds[r.PathValue("kind")]
	if !ok {
		refuse(w, http.StatusNotFound, "unknown kind")
		return
	}
	if !s.allow("u:"+ip, uploadsPerIP, 24*time.Hour) {
		refuse(w, http.StatusTooManyRequests, "too many requests")
		return
	}
	// The request itself: no query, a declared length within the kind's limits, no chunked body.
	if r.ContentLength > k.maxBytes {
		refuse(w, http.StatusRequestEntityTooLarge, "too large")
		return
	}
	if r.URL.RawQuery != "" || r.ContentLength < k.minBytes || len(r.TransferEncoding) > 0 {
		refuse(w, http.StatusBadRequest, "bad request")
		return
	}
	if r.Header.Get("Content-Type") != "application/vnd.nativemons.package+json" {
		refuse(w, http.StatusUnsupportedMediaType, "wrong type")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, k.maxBytes))
	if err != nil {
		refuse(w, http.StatusRequestEntityTooLarge, "too large")
		return
	}
	// The signature first: nothing else in the package is believed before it holds.
	e, err := readEnvelope(body)
	if err != nil {
		refuse(w, http.StatusBadRequest, "bad package")
		return
	}
	if e.Kind != r.PathValue("kind") {
		refuse(w, http.StatusBadRequest, "bad package")
		return
	}
	key, raw, err := parseKey(e.Key)
	if err != nil || !verify(key, body, r.Header.Get("X-NM-Signature")) {
		refuse(w, http.StatusUnauthorized, "bad signature")
		return
	}
	id := keyID(raw)
	if s.store.banned(id) {
		refuse(w, http.StatusForbidden, "not accepted")
		return
	}
	// The challenge: given to this key, not expired, and used only once.
	s.mu.Lock()
	c, found := s.challenges[e.Nonce]
	if found {
		delete(s.challenges, e.Nonce)
	}
	s.mu.Unlock()
	if !found || c.key != id || s.now().After(c.expires) {
		refuse(w, http.StatusUnauthorized, "bad or used challenge")
		return
	}
	created, _ := strconv.ParseInt(e.Created.String(), 10, 64)
	if d := s.now().Sub(time.Unix(created, 0)); d > clockSlack || d < -clockSlack {
		refuse(w, http.StatusBadRequest, "clock")
		return
	}
	if !s.allow("k:"+e.Kind+":"+id, k.perDay, 24*time.Hour) {
		refuse(w, http.StatusTooManyRequests, "too many packages")
		return
	}
	summary, canonical, err := k.check(e.Body)
	if err != nil {
		refuse(w, http.StatusBadRequest, "bad package")
		return
	}
	// The layout: only the bytes the launcher writes, nothing reordered, spaced, escaped or added.
	if !bytes.Equal(body, e.canonical(canonical)) || int64(len(body)) != r.ContentLength {
		refuse(w, http.StatusBadRequest, "bad layout")
		return
	}
	receipt, err := s.store.quarantine(e.Kind, id, ip, summary, body, r.Header.Get("X-NM-Signature"))
	if err != nil {
		log.Printf("quarantine: %v", err)
		refuse(w, http.StatusInternalServerError, "try again")
		return
	}
	log.Printf("queued %s from %s: %s", receipt, id, summary)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"receipt": receipt})
}
