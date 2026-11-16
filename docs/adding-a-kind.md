# Adding a kind of package

A kind is something the launcher can send: Zakuro hint lists are the first. The signing, the challenge, the
rate limits, the quarantine and the review all come for free; a new kind only says what its `body` looks
like and how to check it.

1. **Its own file**, `kind_<name>.go`, with one function:

   ```go
   func check<Name>(body []byte) (summary string, err error) {
       var a string
       var b []string
       if err := parseStrict(body, map[string]any{"a": &a, "b": &b}); err != nil {
           return "", err
       }
       // Check every value: its characters, its length, its range. Refuse anything else.
       return "<one line for the review queue>", nil
   }
   ```

   `parseStrict` already refuses missing, extra and repeated fields and anything after the object; the
   function checks the values. Never use a value as a file name, a path, a command or a URL, and never
   unpack or run anything from a package: a package is data, kept as it came.

2. **One line** in `kinds.go`:

   ```go
   "<name>": {maxBytes: <the largest real one, with room>, perDay: <per install>, check: check<Name>},
   ```

3. **Tests** in `server_test.go` (or `kind_<name>_test.go`): a good package is queued, and each kind of bad
   one is refused and never reaches the queue. Copy `TestGoodPackageIsQueued` and `TestRefused`.

4. **The spec**: a section under "Kinds" in `docs/protocol.md`.

5. **The launcher**: it sends `POST /v1/submit/<name>` with the same envelope; only `kind` and `body` change.

6. **Merging it**: an approved package of the new kind needs its own step that reads it (after checking it
   again) and puts it where it belongs, as `tools/zakuro-hints/merge.ps1 -Package` does in nativeMons.
