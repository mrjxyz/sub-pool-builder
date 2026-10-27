import json, os, base64, urllib.request, urllib.parse, sys

ACCT = "d3ec4927add071e10787034eca883ec0"
KV_TITLE = "sub-server-SUB_KV"
BASE_KEY = "base:config"
LIVE_KEY = "sub:507281a5bc845595"
SUB_URL = "https://agentscope.shaiya.kdns.fr/sub"
TOK = os.environ["CF_API_TOKEN"]
API = "https://api.cloudflare.com/client/v4"
NAMES = {"AGENTSCOPE-VLESS", "AGENTSCOPE-VMess", "AGENTSCOPE-Trojan"}


def call(path, data=None, method=None):
    req = urllib.request.Request(API + path, data=data, method=method)
    req.add_header("Authorization", "Bearer " + TOK)
    with urllib.request.urlopen(req, timeout=90) as r:
        return r.read()


def q(k):
    return urllib.parse.quote(k, safe="")


def to_clash(uri):
    scheme, rest = uri.split("://", 1)
    scheme = scheme.lower()
    if scheme == "vmess":
        c = json.loads(base64.b64decode(rest + "=" * (-len(rest) % 4)).decode())
        path = str(c.get("path") or "/").split("#")[0]
        return {"name": "AGENTSCOPE-VMess", "type": "vmess", "server": c.get("add"),
                "port": int(c.get("port") or 443), "uuid": c.get("id"), "alterId": int(c.get("aid") or 0),
                "cipher": "auto", "udp": True, "tls": True, "servername": c.get("sni") or c.get("host"),
                "client-fingerprint": "chrome", "skip-cert-verify": False, "network": "ws",
                "ws-opts": {"path": path, "headers": {"Host": c.get("host") or c.get("sni")}}}
    frag = rest.split("#", 1)[1] if "#" in rest else ""
    head, query = rest.split("?", 1)
    query = query.split("#")[0]
    params = {}
    for pair in query.split("&"):
        if "=" in pair:
            k, v = pair.split("=", 1)
            params[k] = v
    secret, hostport = head.rsplit("@", 1)
    server = hostport.split(":")[0]
    port = int((hostport.split(":") + ["443"])[1] or 443)
    path = params.get("path", "/").split("#")[0]
    host = params.get("host") or params.get("sni") or server
    if scheme == "vless":
        return {"name": "AGENTSCOPE-VLESS", "type": "vless", "server": server, "port": port,
                "uuid": secret, "udp": True, "tls": True, "servername": params.get("sni") or host,
                "client-fingerprint": "chrome", "skip-cert-verify": False, "network": "ws",
                "packet-encoding": "xudp", "ws-opts": {"path": path, "headers": {"Host": host}}}
    return {"name": "AGENTSCOPE-Trojan", "type": "trojan", "server": server, "port": port,
            "password": secret, "udp": True, "tls": True, "sni": params.get("sni") or host,
            "skip-cert-verify": False, "network": "ws",
            "ws-opts": {"path": path, "headers": {"Host": host}}}


def merge_into_cfg(cfg):
    proxies = cfg.get("proxies") or []
    keep = [p for p in proxies if str(p.get("name")) not in NAMES]
    cfg["proxies"] = keep + MINE
    for g in cfg.get("proxy-groups") or []:
        pl = g.get("proxies")
        if isinstance(pl, list):
            base = [x for x in pl if x not in NAMES]
            g["proxies"] = base + [p["name"] for p in MINE]
    return len(cfg["proxies"])


raw = urllib.request.urlopen(SUB_URL, timeout=60).read().strip()
text = base64.b64decode(raw + b"=" * (-len(raw) % 4)).decode()
MINE = [to_clash(l) for l in text.splitlines() if l.strip()]
print("fetched nodes:", [m["name"] for m in MINE])

ns_list = json.loads(call(f"/accounts/{ACCT}/storage/kv/namespaces?per_page=50"))["result"]
ns = next((n["id"] for n in ns_list if n.get("title") == KV_TITLE), None)
if not ns:
    print("namespace not found")
    sys.exit(3)
print("ns:", ns)

for key in (BASE_KEY, LIVE_KEY):
    try:
        body = call(f"/accounts/{ACCT}/storage/kv/namespaces/{ns}/values/{q(key)}")
    except Exception as e:
        print(key, "read failed", type(e).__name__)
        continue
    if not body:
        print(key, "empty")
        continue
    obj = json.loads(body)
    if key == BASE_KEY:
        total = merge_into_cfg(obj)
        out = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode()
        call(f"/accounts/{ACCT}/storage/kv/namespaces/{ns}/values/{q(key)}", data=out, method="PUT")
        back = json.loads(call(f"/accounts/{ACCT}/storage/kv/namespaces/{ns}/values/{q(key)}"))
        got = {p.get("name") for p in (back.get("proxies") or [])}
    else:
        y = json.loads(obj.get("yaml") or "{}")
        total = merge_into_cfg(y)
        obj["yaml"] = json.dumps(y, ensure_ascii=False, separators=(",", ":"))
        out = json.dumps(obj, ensure_ascii=False).encode()
        call(f"/accounts/{ACCT}/storage/kv/namespaces/{ns}/values/{q(key)}", data=out, method="PUT")
        back = json.loads(call(f"/accounts/{ACCT}/storage/kv/namespaces/{ns}/values/{q(key)}"))
        yy = json.loads(back.get("yaml") or "{}")
        got = {p.get("name") for p in (yy.get("proxies") or [])}
    print(key, "written total=", total, "all3=", NAMES.issubset(got))
print("DONE")
