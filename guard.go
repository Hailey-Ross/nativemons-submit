package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Protections against requests that don't fit the protocol. Every refusal is a strike against the address it
// came from, and against its install once the signature has proven that install sent it (anyone can send
// someone else's public key, so an unproven key is never struck). Too many strikes block the address or the
// install for a day, and a blocked one is turned away before anything it sends is read. Every refusal is
// logged and kept in refusals.log for `review refusals`. Rate limits, server errors and a wrong clock aren't
// refusals of a request's format, so they never count. Blocks are kept in blocks.json, so they outlast a
// restart; `review unblock` lifts one (then restart the service).

const (
	ipStrikeLimit   = 10 // refusals in ipStrikeWindow, then the address is blocked
	ipStrikeWindow  = time.Hour
	keyStrikeLimit  = 5 // refusals in keyStrikeWindow, then the install is blocked
	keyStrikeWindow = 24 * time.Hour
	blockFor        = 24 * time.Hour
	refusalLogMax   = 5 << 20 // bytes; then refusals.log rolls over to refusals.log.1
	sweepEvery      = 10 * time.Minute
)

var reIPTag = regexp.MustCompile(`^[0-9a-f]{24}$`)

type refusal struct {
	Time   string `json:"time"`
	Status int    `json:"status"`
	Reason string `json:"reason"`
	IP     string `json:"ip"`
	Key    string `json:"key,omitempty"`
}

// blockedNow says whether an address ("ip:<tag>") or an install ("key:<id>") is blocked right now.
func (s *server) blockedNow(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	until, ok := s.blocked[name]
	if !ok {
		return false
	}
	if s.now().After(until) {
		delete(s.blocked, name)
		return false
	}
	return true
}

// strike counts one refusal against name; true when this one blocks it.
func (s *server) strike(name string, limit int, window time.Duration) bool {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.counts["s:"+name][:0]
	for _, t := range s.counts["s:"+name] {
		if now.Sub(t) < window {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)
	if len(kept) >= limit {
		delete(s.counts, "s:"+name)
		s.blocked[name] = now.Add(blockFor)
		if err := s.store.saveBlocks(s.blocked, now); err != nil {
			log.Printf("blocks.json: %v", err)
		}
		return true
	}
	s.counts["s:"+name] = kept
	return false
}

// fail refuses a request that doesn't fit, records it, and strikes its address, and its install when key is
// a proven key id.
func (s *server) fail(w http.ResponseWriter, status int, reason, ip, key string) {
	refuse(w, status, reason)
	s.record(status, reason, ip, key)
	if s.strike("ip:"+ip, s.ipStrikes, ipStrikeWindow) {
		s.record(http.StatusTooManyRequests, "address blocked", ip, "")
	}
	if key != "" && s.strike("key:"+key, s.keyStrikes, keyStrikeWindow) {
		s.record(http.StatusTooManyRequests, "install blocked", ip, key)
	}
}

// turnAway answers a blocked address or install. It isn't recorded, so a flood of them can't fill the log.
func turnAway(w http.ResponseWriter) {
	refuse(w, http.StatusTooManyRequests, "blocked")
}

func (s *server) record(status int, reason, ip, key string) {
	who := "address " + ip
	if key != "" {
		who += ", install " + key
	}
	log.Printf("refused %d %s: %s", status, reason, who)
	line, _ := json.Marshal(refusal{Time: s.now().UTC().Format(time.RFC3339), Status: status, Reason: reason, IP: ip, Key: key})
	if err := s.store.logRefusal(append(line, '\n')); err != nil {
		log.Printf("refusals.log: %v", err)
	}
}

// sweep drops what no window can still use, so many addresses can't grow the server's memory for long.
func (s *server) sweep() {
	for range time.Tick(sweepEvery) {
		now := s.now()
		s.mu.Lock()
		for name, times := range s.counts {
			if len(times) == 0 || now.Sub(times[len(times)-1]) >= 24*time.Hour {
				delete(s.counts, name)
			}
		}
		for name, until := range s.blocked {
			if now.After(until) {
				delete(s.blocked, name)
			}
		}
		for nonce, c := range s.challenges {
			if now.After(c.expires) {
				delete(s.challenges, nonce)
			}
		}
		s.mu.Unlock()
	}
}

// logRefusal appends one line to refusals.log, rolling it over to refusals.log.1 once it's full.
func (s *store) logRefusal(line []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	path := filepath.Join(s.dir, "refusals.log")
	if fi, err := os.Stat(path); err == nil && fi.Size()+int64(len(line)) > refusalLogMax {
		if err := os.Rename(path, path+".1"); err != nil {
			return err
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(line)
	return err
}

// refusals reads the refusals since a time, oldest first.
func (s *store) refusals(since time.Time) []refusal {
	var out []refusal
	for _, name := range []string{"refusals.log.1", "refusals.log"} {
		data, err := os.ReadFile(filepath.Join(s.dir, name))
		if err != nil {
			continue
		}
		for _, l := range strings.Split(string(data), "\n") {
			var r refusal
			if json.Unmarshal([]byte(l), &r) != nil {
				continue
			}
			if t, err := time.Parse(time.RFC3339, r.Time); err == nil && !t.Before(since) {
				out = append(out, r)
			}
		}
	}
	return out
}

// printRefusals is `review refusals [hours]`: what was refused, from where, and what got blocked.
func printRefusals(st *store, hours int) {
	rs := st.refusals(time.Now().Add(-time.Duration(hours) * time.Hour))
	fmt.Printf("%d refusals in the last %d hours\n", len(rs), hours)
	if len(rs) == 0 {
		return
	}
	top := func(title string, pick func(refusal) string, n int) {
		counts := map[string]int{}
		for _, r := range rs {
			if v := pick(r); v != "" {
				counts[v]++
			}
		}
		if len(counts) == 0 {
			return
		}
		names := make([]string, 0, len(counts))
		for k := range counts {
			names = append(names, k)
		}
		sort.Slice(names, func(i, j int) bool {
			if counts[names[i]] != counts[names[j]] {
				return counts[names[i]] > counts[names[j]]
			}
			return names[i] < names[j]
		})
		if len(names) > n {
			names = names[:n]
		}
		fmt.Println("\n" + title)
		for _, k := range names {
			fmt.Printf("  %5d  %s\n", counts[k], k)
		}
	}
	top("By reason:", func(r refusal) string { return fmt.Sprintf("%d %s", r.Status, r.Reason) }, 20)
	top("By address (tag):", func(r refusal) string { return r.IP }, 10)
	top("By install (key id, for review ban):", func(r refusal) string { return r.Key }, 10)
	var blocks []string
	for _, r := range rs {
		if r.Reason == "address blocked" {
			blocks = append(blocks, r.Time+"  address "+r.IP)
		} else if r.Reason == "install blocked" {
			blocks = append(blocks, r.Time+"  install "+r.Key)
		}
	}
	if len(blocks) > 0 {
		fmt.Println("\nBlocked for a day:")
		for _, b := range blocks {
			fmt.Println("  " + b)
		}
	}
}

// ipSalt reads the address salt, making it the first time: 32 random bytes only the service's user can read.
func (s *store) ipSalt() ([]byte, error) {
	path := filepath.Join(s.dir, "ipsalt")
	if b, err := os.ReadFile(path); err == nil && len(b) == 32 {
		return b, nil
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	if err := writeAtomic(path, b); err != nil {
		return nil, err
	}
	return b, nil
}

// loadBlocks reads blocks.json, leaving out the ones that have ended. A missing or damaged file is no blocks.
func (s *store) loadBlocks(now time.Time) map[string]time.Time {
	out := map[string]time.Time{}
	data, err := os.ReadFile(filepath.Join(s.dir, "blocks.json"))
	if err != nil {
		return out
	}
	var in map[string]time.Time
	if json.Unmarshal(data, &in) != nil {
		return out
	}
	for name, until := range in {
		if until.After(now) && (strings.HasPrefix(name, "ip:") || strings.HasPrefix(name, "key:")) {
			out[name] = until
		}
	}
	return out
}

// saveBlocks writes the blocks still in force to blocks.json, whole, beside and then renamed.
func (s *store) saveBlocks(blocked map[string]time.Time, now time.Time) error {
	keep := map[string]time.Time{}
	for name, until := range blocked {
		if until.After(now) {
			keep[name] = until.UTC()
		}
	}
	data, err := json.MarshalIndent(keep, "", "  ")
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return writeAtomic(filepath.Join(s.dir, "blocks.json"), data)
}

// unblock lifts a block on an address tag or a key id in blocks.json; the service reads it when it starts.
func (s *store) unblock(who string) (bool, error) {
	if !reKeyID.MatchString(who) && !reIPTag.MatchString(who) {
		return false, errors.New("not an address tag or a key id")
	}
	now := time.Now()
	blocked := s.loadBlocks(now)
	found := false
	for _, name := range []string{"ip:" + who, "key:" + who} {
		if _, ok := blocked[name]; ok {
			delete(blocked, name)
			found = true
		}
	}
	if !found {
		return false, nil
	}
	return true, s.saveBlocks(blocked, now)
}

func writeAtomic(path string, data []byte) error {
	if err := os.WriteFile(path+".part", data, 0o600); err != nil {
		return err
	}
	return os.Rename(path+".part", path)
}
