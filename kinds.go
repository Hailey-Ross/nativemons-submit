package main

// A kind of package: its own size limit, daily limit per install, and check of the body. Adding a kind
// is a file of its own (kind_<name>.go, its check) and one line here; see docs/adding-a-kind.md.
type kind struct {
	maxBytes int64
	perDay   int
	minBytes int64
	// check reads the body (the package's "body" field, still untrusted) and returns a one-line summary
	// for the review queue and the body as the launcher writes it (the one layout accepted), or why it's
	// refused.
	check func(body []byte) (summary string, canonical []byte, err error)
}

var kinds = map[string]kind{
	"zakuro-hints": {minBytes: 300, maxBytes: 768 << 10, perDay: 20, check: checkZakuroHints},
}
