# proxy-chain

**Version 1.0.0**

Local TCP proxy. Point an application at it, and each connection goes out through a proxy you choose from a list. The list can change while the program is running.

GitHub shows this file after you clone the repository. The full manual is [documentation.md](documentation.md).

## Add your Webshare proxies

Webshare gives you a list plus a username and password. Those stay on your machine. They are not part of this git repository.

1. In the Webshare dashboard, download the proxy list as `IP:PORT:USERNAME:PASSWORD`.
2. Copy `proxies.example.txt` to `proxies.txt`.
3. Paste the downloaded lines into `proxies.txt`.
4. Use `scheme http` for Webshare HTTP proxies, or `scheme socks5` for Webshare SOCKS5 proxies.

`proxies.txt` looks like this, with your own values:

```text
scheme http
203.0.113.10:8080:your-username:your-password
203.0.113.11:8080:your-username:your-password
```

A rotating endpoint can be one line, with the shared login in the config:

```text
scheme http
p.webshare.io:80
```

```json
"proxy_username": "your-username",
"proxy_password": "your-password"
```

Put that login in `config.local.json` (also ignored by git), not in the example file.

## Run

```powershell
python -m proxy_chain -c config.example.json
```

`config.example.json` uses mode `dynamic` and `chain_length` 1. Each connection uses one working proxy. If that proxy is down, the next line in `proxies.txt` is tried. Saving `proxies.txt` reloads the list within about a second.

```powershell
curl --socks5-hostname 127.0.0.1:1080 https://example.com
curl -x http://127.0.0.1:1080 https://example.com
```

## Modes

These are the same three categories as ProxyChains, plus round-robin.

| Mode | ProxyChains name | With `chain_length` 1 |
| --- | --- | --- |
| `dynamic` | `dynamic_chain` | First working proxy in the list. Dead lines are skipped. |
| `static` | `strict_chain` | The first proxy only. The connection fails if that proxy is down. |
| `random` | `random_chain` | One proxy chosen at random for each connection. |
| `round_robin` | | The next proxy in the list for each connection. |

`chain_length` 0 uses the whole list as one chain. Leave it at 1 for a Webshare list.

`strict` and `strict_chain` are accepted and mean `static`.

## Clone on a Linux VM

Yes. After this project is on GitHub, the VMware guest only needs git and Python 3.10 or newer.

```bash
git clone https://github.com/YOUR_USER/proxy-chain.git
cd proxy-chain
cp proxies.example.txt proxies.txt
nano proxies.txt
python3 -m proxy_chain -c config.example.json
```

Copy `proxies.txt` onto the VM yourself (editor, shared folder, or `scp`). The clone does not contain your Webshare password.

## Tests

```powershell
python -m unittest discover -s tests -v
```
