# proxy-chain documentation

This is the manual for the local proxy chain. [README.md](README.md) is the short start guide.

The program listens on your machine and forwards TCP connections through proxies from `proxies.txt` or from the config file. You can add, remove, and reorder proxies while it is running. Hostnames are sent to the exit proxy, so DNS for the destination happens there.

Python 3.10 or newer is required. The standard library is enough. No packages need to be installed.

## Modes

ProxyChains has three chain types. This project uses those names, and also accepts the ProxyChains config names.

| Mode | Also accepted | What one connection does |
| --- | --- | --- |
| `dynamic` | `dynamic_chain` | Skips dead proxies. Uses `chain_length` working proxies, in list order. |
| `static` | `strict`, `strict_chain` | Does not skip. Uses the first `chain_length` proxies, or the whole list when `chain_length` is 0. Any failure fails the connection. |
| `random` | `random_chain` | Picks `chain_length` proxies at random. A dead pick is replaced by another try. |
| `round_robin` | `round-robin` | Rotates the start of a window of `chain_length` proxies. |

`chain_length` 0 means "the whole list". For a Webshare list of many proxies, set `chain_length` to 1 so each connection uses one proxy instead of trying to tunnel through every line.

A destination that refuses the connection does not remove a proxy that answered. A proxy that cannot be reached is cooled down and skipped by `dynamic`, `random`, and `round_robin` until the cooldown ends or a later connection succeeds.

With a proxy list, the defaults are `min_hops` 1 and `allow_direct` false. Traffic is not sent directly from this machine when the list fails. Set both `min_hops` to 0 and `allow_direct` to true only if a direct fallback is what you want. `--allow-direct` sets that pair unless you also pass `--min-hops`.

## Proxy list

Create `proxies.txt` next to the program. Git ignores that file. Start from `proxies.example.txt`.

Blank lines and lines starting with `#` are ignored. A `scheme` line applies to the lines under it:

```text
scheme http
203.0.113.10:8080:username:password
203.0.113.11:8080:username:password

scheme socks5
203.0.113.12:1080:username:password
```

Accepted line shapes:

| Line | Example |
| --- | --- |
| Webshare download | `203.0.113.10:8080:username:password` |
| Login in front | `username:password@203.0.113.10:8080` |
| Full URL | `http://username:password@203.0.113.10:8080` |
| Host and port only | `203.0.113.10:8080` |

Host-and-port lines use `proxy_scheme`, `proxy_username`, and `proxy_password` from the config or the command line. A password may contain extra colons; everything after the username is the password.

`proxy_scheme` is the scheme for lines that do not name one. Webshare HTTP proxies use `http`. Webshare SOCKS5 proxies use `socks5`. The port is the port in the downloaded list (often 80 for HTTP and 1080 for SOCKS5, but use the port Webshare shows).

The JSON config can also contain a `proxies` array of URLs. Those entries are used first, then the lines in `proxy_list`. Duplicate entries are kept once.

Saving `proxies.txt` or the config file reloads the pool in about a second. The listen port does not change until you restart.

You can also change the live pool without editing the file. See the control API below.

## Config

`config.example.json` is a working file once `proxies.txt` exists.

| Field | Meaning |
| --- | --- |
| `listen.host`, `listen.port` | Local address. Default `127.0.0.1:1080`. |
| `mode` | `dynamic`, `static`, `random`, or `round_robin`. |
| `chain_length` | Hops per connection. `1` for a Webshare list. `0` for the whole list. |
| `min_hops` | Minimum proxies a connection must use. |
| `allow_direct` | Allow a direct connection when `min_hops` is 0 and nothing is usable. |
| `proxy_list` | Path of the text file. Relative paths are next to the config file. |
| `proxy_scheme` | `http`, `https`, `socks5`, or `socks4`. |
| `proxy_username`, `proxy_password` | Login for lines that omit one. Leave empty when every line has its own login. |
| `connect_timeout` | Seconds to connect to a proxy or destination. |
| `handshake_timeout` | Seconds to read the client's first request. |
| `idle_timeout` | Seconds a tunnel may sit idle. |
| `max_connections` | Simultaneous client connections. |
| `auth.username`, `auth.password` | Login required of local clients. Empty username disables it. |
| `control.enabled`, `control.host`, `control.port`, `control.token` | Local control API. |
| `health.enabled`, `health.interval`, `health.timeout`, `health.cooldown` | Background TCP probes and how long a dead proxy stays aside. |
| `proxies` | Optional extra proxies as URLs or `{"id", "url", "username", "password", "enabled"}`. |

`https` means TLS to the proxy, then HTTP CONNECT. Add `?tls_verify=0` on a URL that uses a certificate this machine does not trust.

Copy secrets into `config.local.json` and run `python -m proxy_chain -c config.local.json` if you do not want them in `config.example.json`. `config.local.json` is gitignored.

## Command line

```text
python -m proxy_chain -c config.example.json
python -m proxy_chain --proxy-list proxies.txt --proxy-scheme http --mode dynamic --chain-length 1
python -m proxy_chain --proxy socks5://127.0.0.1:9050 --mode static
```

| Flag | Meaning |
| --- | --- |
| `-c`, `--config` | JSON config file. |
| `--listen host:port` | Local listen address. |
| `--proxy-list` | Proxy file. Replaces the proxy set for this run. |
| `--proxy-scheme` | Scheme for lines without one. |
| `--proxy-user`, `--proxy-password` | Login for lines without one. |
| `--proxy` | One proxy URL. Repeat for several. Combined with `--proxy-list` when both are set. |
| `--mode` | `dynamic`, `static`, `random`, or `round_robin`. |
| `--chain-length` | Hops per connection. |
| `--min-hops` | Minimum hop count. |
| `--allow-direct` | Permit a direct connection and set `min_hops` to 0 unless `--min-hops` is set. |
| `--no-direct` | Never connect directly. |
| `--control host:port` or `--control off` | Control API. |
| `--token` | Bearer token for the control API. |
| `--user`, `--password` | Login for local clients. |
| `--no-health` | Disable background probes. |
| `-v` | Debug logging. |

## Control API

Default address: `127.0.0.1:1081`. If `control.token` is set, send `Authorization: Bearer <token>`.

| Request | Effect |
| --- | --- |
| `GET /status` | Mode, proxy count, counters, recent destinations, proxy list path. |
| `GET /proxies` | Proxies currently loaded. Passwords are not included. |
| `POST /proxies` | Add a proxy. Body `{"url": "http://user:pass@203.0.113.10:8080"}` or a Webshare-style object `{"url": "http://203.0.113.10:8080", "username": "user", "password": "pass"}`. |
| `PATCH /proxies/<id>` | Body `{"enabled": false}`. |
| `DELETE /proxies/<id>` | Remove one proxy. |
| `POST /reorder` | Body `{"ids": ["b", "a"]}`. The list must contain every current id once. |
| `POST /mode` | Change `mode`, `chain_length`, `min_hops`, `allow_direct`, or `connect_timeout`. |
| `POST /reload` | Read the config file and proxy list again. |
| `POST /health/check` | Probe every proxy now. |

```powershell
curl http://127.0.0.1:1081/status
curl -X POST http://127.0.0.1:1081/mode -H "Content-Type: application/json" -d "{\"mode\": \"random\", \"chain_length\": 1}"
```

`GET /status` keeps the last 200 destination host/port pairs for this process. It does not record page contents or passwords.

## Local client protocols

The listen port accepts all of these on the same port. The first byte selects the protocol.

- SOCKS5, including username and password when `auth` is set
- SOCKS4 and SOCKS4a when local auth is off
- HTTP `CONNECT` for HTTPS
- One plain HTTP request, rewritten and then closed

UDP and SOCKS `BIND` are refused.

Upstream proxies can be SOCKS5, SOCKS4, HTTP CONNECT, or TLS-wrapped HTTP CONNECT.

## Linux VM

Cloning onto a VMware Linux guest works. The guest needs a network path to GitHub and to the proxies.

```bash
sudo apt update
sudo apt install -y git python3
git clone https://github.com/YOUR_USER/proxy-chain.git
cd proxy-chain
python3 --version
cp proxies.example.txt proxies.txt
nano proxies.txt
python3 -m proxy_chain -c config.example.json
```

`python3 --version` must be 3.10 or newer. On an older guest, install a newer Python before starting the program.

Create `proxies.txt` on the VM, or copy it from Windows with a VMware shared folder or `scp`. Do not commit that file and then pull it. The repository is supposed to stay free of proxy passwords.

From another program on the same VM, use `127.0.0.1:1080`. From the Windows host, use the guest's IP only if you change `listen.host` and set `auth`. The default bind is loopback, so the Windows host cannot reach it until you do that on purpose.

## Tests

```bash
python -m unittest discover -s tests -v
```

The tests cover a two-hop chain, dead-proxy failover, one-proxy dynamic selection, round-robin, random selection, HTTP and SOCKS4 upstreams, a TLS upstream when the `cryptography` package is installed, the Webshare line formats, and the control API.

## Documentation updates

`README.md` and this file are part of the project. A change to behavior, the proxy list, the modes, the command line, or the control API is supposed to update both documents in the same change. A Cursor rule in `.cursor/rules/update-docs.mdc` tells the editor to do that, and `.cursor/hooks/update-docs.py` asks for the update if code was saved without those files.
