# The submission protocol (v1)

How a nativeMons launcher sends a package to `https://submit.hails.app`. Every byte of a request is
untrusted: the server checks each rule below and refuses anything else, with a short reason and nothing
echoed back.

## 1. The install's key

Each launcher install makes one ECDSA P-256 key the first time it shares something, and keeps it encrypted
for the Windows user (DPAPI). Its public half goes in every request as the uncompressed point (`0x04`, X,
Y: 65 bytes) in standard base64. The server names an install by its key id: the first 16 bytes of the
SHA-256 of those 65 bytes, in hex. Rate limits and bans go by key id.

## 2. A challenge

```
POST /v1/challenge
Content-Type: application/json

{"key": "<base64 key>"}
```

Answer: `{"nonce": "<base64 32 bytes>", "expires": <unix seconds>}`. A challenge belongs to that key, lasts
5 minutes, and works once. At most 30 challenges an hour per address. A banned key gets `403`.

## 3. The package

```
POST /v1/submit/<kind>
Content-Type: application/vnd.nativemons.package+json
X-NM-Signature: <base64 r||s, 64 bytes>

{"v":1,"kind":"<kind>","key":"<base64 key>","nonce":"<the challenge>","created":<unix seconds>,
 "launcher":"<launcher version>","zakuro":"<zakuro build>","body":{ ...the kind's own shape... }}
```

- The signature is ECDSA P-256 over the SHA-256 of the exact request body, as `r||s` (32 bytes each),
  which is what .NET's `ECDsa.SignData(data, HashAlgorithmName.SHA256)` returns.
- The order the server checks in: the kind exists, the address isn't over its limit (60 packages a day),
  the content type, the size (each kind has a limit, read no further), the outer shape, the signature over
  the exact bytes, the key isn't banned, the challenge (this key's, unexpired, unused), the clock (within
  10 minutes), the key's daily limit for the kind, then the kind's own check of `body`.
- Every object, outer and inner, must have exactly its fields: none missing, none extra, none twice, and
  nothing after it.
- **One layout only.** The package must be byte for byte what the launcher writes: the fields in the order
  shown, no spaces or line breaks, no escape sequences, no trailing newline. The server rebuilds the package
  from its checked values and refuses it unless the bytes match exactly.
- **The request itself:** a declared `Content-Length` within the kind's minimum and maximum (no chunked
  body), no query string, and exactly the content type above. The challenge request is likewise exactly
  `{"key":"<base64 key>"}`.
- `launcher`: 1 to 80 of `A-Z a-z 0-9 space . , ( ) -`. `zakuro`: 7 to 40 lowercase hex digits, or `unknown`.

Answer: `202 {"receipt": "<yyyymmdd>-<16 hex>"}`. The package waits in the review queue; nothing reaches
the shared lists until it's approved.

## Kinds

### `zakuro-hints`

```
{"code": "<title id>-<code hash>", "addresses": ["0010A7C8", "0016D6B4", ...]}
```

- `code`: 16 uppercase hex digits, a dash, 16 more; the title id must be one 3DSrecomp+Zakuro builds.
- `addresses`: 1 to 65536, each 8 uppercase hex digits, inside a title's code (`0x00100000` up to
  `0x10000000`, odd for Thumb), in rising order with no repeats.
- From 300 bytes up to 768 KB, 20 a day per install. The body is exactly
  `{"code":"...","addresses":["...","..."]}`.
