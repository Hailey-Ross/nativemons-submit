# Deploying submit.hails.app

On the same server as hailsDotGO, behind its Caddy. Nothing here needs a database or secrets: the service
keeps its queue in files, and the keys it checks come from the launchers.

## First install (once, on the server)

1. DNS: an `A` (and `AAAA`) record for `submit.hails.app` pointing at the server.
2. A user with no shell and the folders:
   ```
   sudo useradd --system --no-create-home --shell /usr/sbin/nologin nmsubmit
   sudo mkdir -p /opt/nativemons-submit/data
   sudo chown -R nmsubmit:nmsubmit /opt/nativemons-submit/data
   sudo chmod 700 /opt/nativemons-submit/data
   ```
3. The service: copy `nativemons-submit.service` to `/etc/systemd/system/`, then
   `sudo systemctl daemon-reload && sudo systemctl enable nativemons-submit`.
4. Caddy: add the block in `Caddyfile` to the server's Caddyfile and `sudo systemctl reload caddy`. Caddy
   gets the TLS certificate on its own.

## Each deploy

`deploy.ps1` builds the Linux binary, runs the tests first, copies the binary and the service file, and
restarts the service. It reads `VPS_HOST`, `VPS_USER` and `SSH_KEY` from a `.env` beside it (see
`.env.example`; `.env` is never committed).

## Reviewing

On the server, as the service's user:
```
sudo -u nmsubmit NMSUBMIT_DATA=/opt/nativemons-submit/data /opt/nativemons-submit/nativemons-submit review list
... review show <receipt> | approve <receipt> | reject <receipt> | ban <key id> | unblock <tag|key id> | refusals [hours]
```
`review refusals` shows what was turned away in the last day: by reason, by address tag, by install, and the
addresses and installs blocked for a day. An install that keeps getting blocked is one to `ban`. Blocks are
kept in `data/blocks.json` and the address salt in `data/ipsalt`, so a restart or a deploy changes neither.
To lift a block early: `review unblock <address tag or key id>`, then `sudo systemctl restart
nativemons-submit`.
An approved package is in `data/approved/<receipt>.package`; nativeMons' `tools/zakuro-hints/merge.ps1
-Package <file>` checks it again and merges it into the hints branch.

## Check it's up

`curl https://submit.hails.app/v1/health` answers `ok`.
