# nativemons-submit

The submission service at **submit.hails.app**. It takes signed packages from the
[nativeMons](https://github.com/Hailey-Ross/nativeMons) launcher, checks everything about them, and keeps
them in a review queue. Zakuro hint lists (where a 3DS game's build ran code the slow way) are the first
kind; more kinds can be added.

It trusts nothing it's sent:
- Each install signs every package with its own key, and every package needs a one-time challenge from the
  server, so a package can't be changed, replayed or sent in another install's name.
- The size is limited before anything is read, every object must have exactly its fields, and every value
  is checked (characters, lengths, ranges, order).
- Packages are data only: stored under names the server makes, never run, unpacked or used as a path.
- Rate limits per address and per install, and banned keys. Addresses are kept only as a salted hash.
- Nothing reaches nativeMons until a person approves it.

## Docs

- [The protocol](docs/protocol.md): the key, the challenge, the package, each kind's shape.
- [Adding a kind](docs/adding-a-kind.md): a new kind of package in one file.
- [Deploying](deploy/README.md): the server set-up, the service and the Caddy site.

## Use

```
nativemons-submit serve                      listens on NMSUBMIT_LISTEN (127.0.0.1:8087), data in NMSUBMIT_DATA
nativemons-submit review list [approved|rejected]
nativemons-submit review show <receipt>      the package, after its checks again
nativemons-submit review approve <receipt>   to approved/, for the merge in nativeMons
nativemons-submit review reject <receipt>
nativemons-submit review ban <key id>
```

`NMSUBMIT_TRUST_PROXY=1` reads the client's address from Caddy's `X-Forwarded-For`, only for requests
from this machine.

## Build and test

```
go test ./...
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o nativemons-submit .
```

No dependencies beyond Go's standard library.

## License

GPL-3.0-or-later, as nativeMons.
