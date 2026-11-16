package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"regexp"
	"strconv"
)

// A package as it arrives: the exact bytes, signed by the install's key over SHA-256, the signature as
// r||s (64 bytes, what .NET's ECDsa.SignData gives).
type envelope struct {
	V        json.Number     `json:"v"`
	Kind     string          `json:"kind"`
	Key      string          `json:"key"`
	Nonce    string          `json:"nonce"`
	Created  json.Number     `json:"created"`
	Launcher string          `json:"launcher"`
	Zakuro   string          `json:"zakuro"`
	Body     json.RawMessage `json:"body"`
}

var (
	reLauncher = regexp.MustCompile(`^[A-Za-z0-9 .,()\-]{1,80}$`)
	reZakuro   = regexp.MustCompile(`^([0-9a-f]{7,40}|unknown)$`)
	reB64Key   = regexp.MustCompile(`^[A-Za-z0-9+/]{86}[AEIMQUYcgkosw048]=$`)
	reB64Nonce = regexp.MustCompile(`^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$`)
	reUnix     = regexp.MustCompile(`^[1-9][0-9]{9}$`)
)

// canonical is the one layout a package may have: the launcher's, field for field and byte for byte.
// Values are already checked to hold no quotes, backslashes or other characters that would need escaping.
func (e *envelope) canonical(body []byte) []byte {
	return []byte(`{"v":1,"kind":"` + e.Kind + `","key":"` + e.Key + `","nonce":"` + e.Nonce + `","created":` + e.Created.String() +
		`,"launcher":"` + e.Launcher + `","zakuro":"` + e.Zakuro + `","body":` + string(body) + `}`)
}

// parseKey reads an uncompressed P-256 point (0x04, X, Y: 65 bytes) and checks it's on the curve.
func parseKey(b64 string) (*ecdsa.PublicKey, []byte, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(b64)
	if err != nil || len(raw) != 65 || raw[0] != 4 {
		return nil, nil, errors.New("bad key")
	}
	x, y := new(big.Int).SetBytes(raw[1:33]), new(big.Int).SetBytes(raw[33:])
	curve := elliptic.P256()
	if !curve.IsOnCurve(x, y) {
		return nil, nil, errors.New("key not on the curve")
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, raw, nil
}

// keyID names an install by its key: the first 16 bytes of the key's SHA-256, in hex.
func keyID(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:16])
}

func verify(key *ecdsa.PublicKey, body []byte, sigB64 string) bool {
	sig, err := base64.StdEncoding.Strict().DecodeString(sigB64)
	if err != nil || len(sig) != 64 {
		return false
	}
	r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
	sum := sha256.Sum256(body)
	return ecdsa.Verify(key, sum[:], r, s)
}

// readEnvelope checks the outer shape; the body is left to the kind's own check.
func readEnvelope(body []byte) (*envelope, error) {
	var e envelope
	if err := parseStrict(body, map[string]any{
		"v": &e.V, "kind": &e.Kind, "key": &e.Key, "nonce": &e.Nonce, "created": &e.Created,
		"launcher": &e.Launcher, "zakuro": &e.Zakuro, "body": &e.Body,
	}); err != nil {
		return nil, err
	}
	if e.V.String() != "1" {
		return nil, errors.New("unknown version")
	}
	if !reUnix.MatchString(e.Created.String()) {
		return nil, errors.New("bad time")
	}
	if _, err := strconv.ParseInt(e.Created.String(), 10, 64); err != nil {
		return nil, errors.New("bad time")
	}
	if !reB64Key.MatchString(e.Key) || !reB64Nonce.MatchString(e.Nonce) {
		return nil, errors.New("bad key or nonce")
	}
	if !regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`).MatchString(e.Kind) {
		return nil, errors.New("bad kind")
	}
	if !reLauncher.MatchString(e.Launcher) || !reZakuro.MatchString(e.Zakuro) {
		return nil, errors.New("bad version strings")
	}
	if len(e.Body) == 0 || string(e.Body) == "null" {
		return nil, errors.New("no body")
	}
	return &e, nil
}
