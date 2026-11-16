package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// The data folder: queue/<receipt>.package (the exact bytes), .sig (its signature, checked, kept so a merge can
// check it again) and .json (what the server noted), then
// approved/ or rejected/ after review, and banned.txt (one key id a line). Names are always the server's.
type store struct {
	dir string
	mu  sync.Mutex
}

type meta struct {
	Receipt  string `json:"receipt"`
	Kind     string `json:"kind"`
	Key      string `json:"key"`
	IPTag    string `json:"ip_tag"`
	Summary  string `json:"summary"`
	Received string `json:"received"`
	Bytes    int    `json:"bytes"`
}

var reReceipt = regexp.MustCompile(`^[0-9]{8}-[0-9a-f]{16}$`)
var reKeyID = regexp.MustCompile(`^[0-9a-f]{32}$`)

func openStore(dir string) (*store, error) {
	for _, d := range []string{"queue", "approved", "rejected"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o700); err != nil {
			return nil, err
		}
	}
	return &store{dir: dir}, nil
}

func (s *store) banned(id string) bool {
	data, err := os.ReadFile(filepath.Join(s.dir, "banned.txt"))
	if err != nil {
		return false
	}
	for _, l := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(l) == id {
			return true
		}
	}
	return false
}

func (s *store) ban(id string) error {
	if !reKeyID.MatchString(id) {
		return errors.New("not a key id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.OpenFile(filepath.Join(s.dir, "banned.txt"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(id + "\n")
	return err
}

// quarantine keeps the package as data only: written beside, then renamed, never run or unpacked.
func (s *store) quarantine(kind, key, ipTag, summary string, body []byte, sig string) (string, error) {
	r := make([]byte, 8)
	if _, err := rand.Read(r); err != nil {
		return "", err
	}
	now := time.Now().UTC()
	receipt := now.Format("20060102") + "-" + hex.EncodeToString(r)
	m, _ := json.MarshalIndent(meta{Receipt: receipt, Kind: kind, Key: key, IPTag: ipTag, Summary: summary,
		Received: now.Format(time.RFC3339), Bytes: len(body)}, "", "  ")
	base := filepath.Join(s.dir, "queue", receipt)
	for _, f := range []struct {
		path string
		data []byte
	}{{base + ".package", body}, {base + ".sig", []byte(sig)}, {base + ".json", m}} {
		if err := os.WriteFile(f.path+".part", f.data, 0o600); err != nil {
			return "", err
		}
		if err := os.Rename(f.path+".part", f.path); err != nil {
			return "", err
		}
	}
	return receipt, nil
}

func (s *store) list(where string) ([]meta, error) {
	files, err := filepath.Glob(filepath.Join(s.dir, where, "*.json"))
	if err != nil {
		return nil, err
	}
	var out []meta
	for _, f := range files {
		var m meta
		if data, err := os.ReadFile(f); err == nil && json.Unmarshal(data, &m) == nil {
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Receipt < out[j].Receipt })
	return out, nil
}

// move takes a queued package to approved/ or rejected/.
func (s *store) move(receipt, to string) error {
	if !reReceipt.MatchString(receipt) {
		return errors.New("not a receipt")
	}
	for _, ext := range []string{".package", ".sig", ".json"} {
		if err := os.Rename(filepath.Join(s.dir, "queue", receipt+ext), filepath.Join(s.dir, to, receipt+ext)); err != nil {
			return err
		}
	}
	return nil
}
