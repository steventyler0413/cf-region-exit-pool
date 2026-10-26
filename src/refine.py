"""Deep refine: L1 latency, L2 stability, L3 egress-validity,
L4 = VLESS-WS tunnel speed test (download 2MB through the node, record mbps).
L4 runs only when --l4 passed (on a clean-egress runner; 22 egress is throttled).
"""
import zipfile, io, json, time, socket, ssl, base64, os, urllib.request, urllib.parse, ipaddress, struct, sys
from concurrent.futures import ThreadPoolExecutor

UUID_HEX="d37f6de7d1b24fe6a321242878dca3b8"
VLESS_UUID="d37f6de7-d1b2-4fe6-a321-242878dca3b8"
WS_SNI="edgetunnel-hk.dreamtimecloudshare.com"
WS_PATH="/"

def fetch_zip(url, timeout=180):
    """Fetch seed ZIP. The domain 302-redirects to /ip.zip; urllib follows it
    automatically. Full browser headers to avoid 403."""
    hdrs = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/120.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    }
    last = None
    import time as _time
    for attempt in range(3):
        try:
            req = urllib.request.Request(url, headers=hdrs)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                data = r.read()
            if data[:4] == b"PK\x03\x04":
                return data
            last = f"not a zip ({len(data)} bytes)"
        except Exception as ex:
            last = str(ex)
        _time.sleep(1 + attempt)
    raise RuntimeError(f"fetch_zip failed after 3 tries: {last}")


def build_buckets(zip_bytes, targets, ports):
    z = zipfile.ZipFile(io.BytesIO(zip_bytes))
    buckets = {(r, p): [] for r in targets for p in ports}
    for fn in z.namelist():
        if not fn.endswith(".txt"):
            continue
        parts = fn.split("/")
        port = parts[0]
        region = parts[-1].replace(".txt", "")
        if region not in targets or port not in ports:
            continue
        for ip in [l.strip() for l in z.read(fn).decode(errors="replace").splitlines() if l.strip()]:
            buckets[(region, port)].append(ip)
    return buckets

def stable_probe(ip, port, attempts=3, timeout=2):
    lats = []
    for _ in range(attempts):
        t0 = time.time()
        s = socket.socket()
        s.settimeout(timeout)
        try:
            ok = s.connect_ex((ip, int(port))) == 0
        except Exception:
            ok = False
        finally:
            s.close()
        if ok:
            lats.append((time.time() - t0) * 1000)
        time.sleep(0.05)
    if not lats:
        return None
    return {"avg_ms": round(sum(lats) / len(lats), 1), "rate": round(len(lats) / attempts, 2)}

def l3_egress_valid(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_global and not a.is_private and not a.is_loopback
    except ValueError:
        return False

def _ws_handshake(ws, sni):
    key = base64.b64encode(os.urandom(16)).decode()
    req = (f"GET {WS_PATH} HTTP/1.1\r\nHost: {sni}\r\nUpgrade: websocket\r\n"
           f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
           f"Sec-WebSocket-Version: 13\r\n\r\n")
    ws.sendall(req.encode())
    ws.settimeout(6)
    buf = b""
    try:
        while b"\r\n\r\n" not in buf and len(buf) < 4096:
            ch = ws.recv(1024)
            if not ch:
                break
            buf += ch
    except socket.timeout:
        pass
    return b"\r\n\r\n" in buf and ("101" in buf.split(b"\r\n")[0].decode(errors="replace"))

def _ws_send_binary(ws, payload):
    masked = os.urandom(4)
    ln = len(payload)
    f = bytearray()
    f.append(0x82)
    if ln < 126:
        f.append(0x80 | ln)
    elif ln < 65536:
        f.append(0x80 | 126); f += struct.pack(">H", ln)
    else:
        f.append(0x80 | 127); f += struct.pack(">Q", ln)
    f += masked
    f += bytes(b ^ masked[i % 4] for i, b in enumerate(payload))
    ws.sendall(bytes(f))

def _build_vless_connect(target_ip, target_port, cmd=1):
    b = bytearray()
    b.append(0)
    b += bytes.fromhex(UUID_HEX)
    b.append(cmd)          # 1 = connect, 2 = send, 3 = disconnect
    b.append(1)           # type: ipv4
    b += socket.inet_aton(target_ip)
    b += struct.pack(">H", target_port)
    return bytes(b)

def _resolve_ip(host):
    """Resolve a host (domain or IP) to a plain IPv4 string for the VLESS connect frame."""
    import socket as _sk
    if _sk.inet_aton(host) and host.count(".") == 3 and host.isalnum() if host.isdigit() else False:
        pass
    # simplest: try inet_aton (works if it's already an IP), else gethostbyname
    try:
        _sk.inet_aton(host)
        return host  # already an IPv4
    except OSError:
        try:
            return _sk.gethostbyname(host)
        except Exception:
            return host  # leave as-is; caller will fail the L4 test

class _TunnelSocket:
    """Minimal socket-like object that proxies read/write through an already
    established VLESS-WS tunnel (an ssl-wrapped WebSocket). Used to run an
    *inner* TLS handshake on top of the tunnel, so we can reach TLS-only
    targets (like spurl behind Cloudflare)."""
    def __init__(self, underlying, timeout=15):
        self._s = underlying
        self._buf = b""
        self._closed = False
        self._s.settimeout(timeout)
    def fileno(self):
        return -1  # signals not a real fd; ssl will use makefile paths
    def settimeout(self, v):
        self._s.settimeout(v)
    def recv(self, n, flags=0):
        if self._closed:
            raise OSError("tunnel closed")
        if self._buf:
            chunk = self._buf[:n]
            self._buf = self._buf[len(chunk):]
            return chunk
        try:
            return self._s.recv(n, flags)
        except Exception as ex:
            raise OSError(str(ex))
    def sendall(self, data, flags=0):
        if self._closed:
            raise OSError("tunnel closed")
        self._s.sendall(data, flags)
    def send(self, data, flags=0):
        self.sendall(data, flags)
        return len(data)
    def close(self):
        self._closed = True
    def __getattr__(self, name):
        return getattr(self._s, name)

def _ws_recv_binary(ws):
    """Read one binary WebSocket frame (client->server is masked, server->client
    is not). Returns payload bytes. Handles 7/16/64-bit lengths."""
    import struct as _st
    b1 = ws.recv(1)
    b2 = ws.recv(1)
    if not b1 or not b2:
        return b""
    op = b1[0] & 0x0F
    ln = b2[0] & 0x7F
    if ln == 126:
        ln = _st.unpack(">H", ws.recv(2))[0]
    elif ln == 127:
        ln = _st.unpack(">Q", ws.recv(8))[0]
    masked = b2[0] & 0x80
    key = ws.recv(4) if masked else b""
    payload = b""
    got = 0
    while got < ln:
        chunk = ws.recv(ln - got)
        if not chunk:
            break
        payload += chunk
        got += len(chunk)
    if masked:
        unmask = bytes(payload[i] ^ key[i % 4] for i in range(len(payload)))
        return unmask
    return payload

def _ws_send_text_bin(ws, payload):
    """Send a binary WS frame (client->server, masked)."""
    import struct as _st
    m = os.urandom(4)
    ln = len(payload)
    f = bytearray([0x82])
    if ln < 126:
        f.append(0x80 | ln)
    elif ln < 65536:
        f.append(0x80 | 126); f += _st.pack(">H", ln)
    else:
        f.append(0x80 | 127); f += _st.pack(">Q", ln)
    f += m
    f += bytes(payload[i] ^ m[i % 4] for i in range(ln))
    ws.sendall(bytes(f))

def l4_vless_speed(ip, port, mb=5, sni=WS_SNI):
    """Simulate a full v2ray client:
       VLESS-WS tunnel to ip:port -> VLESS connect to spurl IP:443
       -> inner TLS handshake (spurl is behind CF) -> GET /5mb -> measure bw."""
    res = {"mbps": 0.0, "ws_ok": False}
    tgt_host = "spurl.api.030101.xyz"
    tgt_ip = _resolve_ip(tgt_host)
    if not tgt_ip or tgt_ip == tgt_host:
        return res
    try:
        s = socket.create_connection((ip, int(port)), timeout=8)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        w = ctx.wrap_socket(s, server_hostname=sni)
        if not _ws_handshake(w, sni):
            w.close()
            return res
        res["ws_ok"] = True
        # VLESS connect frame (raw VLESS bytes, NOT a WS frame yet -- the server
        # expects VLESS payloads as WS binary frames)
        _ws_send_binary(w, _build_vless_connect(tgt_ip, 443))
        # Now run inner TLS over the tunnel: wrap a TunnelSocket around `w`.
        # VLESS payload bytes travel inside WS binary frames, but for the inner
        # TLS handshake we must send each TLS record as a WS binary frame and
        # read server->client WS frames for replies. We implement this by
        # monkey-patching w's recv/sendall at the TLS layer via TunnelSocket,
        # where sendall = "wrap in a WS binary frame" and recv = "read next
        # WS binary frame".
        class _WsTunnel:
            def __init__(self, ws, timeout=20):
                self.ws = ws
                self.ws.settimeout(timeout)
            def fileno(self): return -1
            def settimeout(self, v): self.ws.settimeout(v)
            def sendall(self, data, *a, **k):
                _ws_send_text_bin(self.ws, bytes(data))
            def send(self, data, *a, **k):
                self.sendall(data); return len(data)
            def recv(self, n, *a, **k):
                return _ws_recv_binary(self.ws)
            def close(self):
                try: self.ws.close()
                except: pass
        wst = _WsTunnel(w, timeout=20)
        ictx = ssl.create_default_context()
        ictx.check_hostname = False
        ictx.verify_mode = ssl.CERT_NONE
        itls = ictx.wrap_socket(wst, server_hostname=tgt_host, do_handshake_on_connect=True)
        # Send HTTP GET /5mb through the inner TLS
        req = f"GET /{mb}mb HTTP/1.1\r\nHost: {tgt_host}\r\nConnection: close\r\n\r\n"
        itls.sendall(req.encode())
        itls.settimeout(20)
        got = 0
        t_dl = time.time()
        while got < mb * 1024 * 1024:
            try:
                chunk = itls.recv(65536)
            except (socket.timeout, OSError, ssl.SSLError):
                break
            if not chunk:
                break
            got += len(chunk)
        dt = max(time.time() - t_dl, 0.001)
        res["mbps"] = round(got * 8 / 1e6 / dt, 1) if got else 0.0
        res["ws_ok"] = got > 0
        try: itls.close()
        except: pass
    except Exception:
        pass
    return res



def run(config_path="config.json", out="data/refined.json", l4=False):
    cfg = json.load(open(config_path))
    zip_bytes = fetch_zip(cfg["source"])
    buckets = build_buckets(zip_bytes, cfg["targets"], cfg["refine_ports"])
    tasks = set()
    for (r, p), ips in buckets.items():
        for ip in ips:
            tasks.add((ip, p))
    all_tasks = list(tasks)
    print(f"refining {len(all_tasks)} (ip,port)", flush=True)

    t0 = time.time()
    with ThreadPoolExecutor(max_workers=cfg.get("max_workers", 128)) as ex:
        futs = {t: ex.submit(stable_probe, t[0], t[1], cfg.get("attempts", 3), cfg.get("timeout_s", 2)) for t in all_tasks}
        stats = {t: fut.result() for t, fut in futs.items()}
    alive = [(t, s) for t, s in stats.items() if s]
    print(f"L1/L2 alive: {len(alive)} ({time.time()-t0:.0f}s)", flush=True)

    l3 = [(t, s) for t, s in alive if l3_egress_valid(t[0])]
    print(f"L3 egress-valid: {len(l3)}", flush=True)

    top_per_region = cfg.get("top_per_region", 10)
    if l4:
        from collections import defaultdict
        by_reg = defaultdict(list)
        for (ip, port), s in l3:
            regs = [r for r in cfg["targets"] if ip in buckets.get((r, "443"), []) + buckets.get((r, "8443"), [])]
            for reg in regs:
                by_reg[reg].append((ip, port, s["avg_ms"], s))
        top_tasks = []
        for reg in cfg["targets"]:
            for (ip, port, avg_ms, s) in sorted(by_reg.get(reg, []), key=lambda x: x[2])[:top_per_region]:
                top_tasks.append((ip, port, s, reg))
        tv = time.time()
        with ThreadPoolExecutor(max_workers=12) as ex:
            sp = {(t[0], t[1]): ex.submit(l4_vless_speed, t[0], t[1], cfg.get("l4_mb", 2)) for t in top_tasks}
            for (ip, port, s, reg) in top_tasks:
                r = sp[(ip, port)].result()
                s["mbps"] = r["mbps"]
                s["ws_ok"] = r["ws_ok"]
            # mark non-top tasks
            topset = {t[:2] for t in top_tasks}
            for (ip, port), s in l3:
                if (ip, port) not in topset:
                    s["mbps"] = None
                    s["ws_ok"] = None
        print(f"L4 done in {time.time()-tv:.0f}s: ws_ok={sum(1 for _,_,s,_ in top_tasks if s.get('ws_ok'))}, "
              f"mbps>0={sum(1 for _,_,s,_ in top_tasks if (s.get('mbps') or 0) > 0)}", flush=True)
        # Keep only items that passed L4 (ws_ok and mbps>0), or all if L4 off
        l3 = [(t, s) for t, s in l3 if s.get("mbps") is None or s.get("ws_ok")]
    else:
        for _, s in l3:
            s["mbps"] = None
            s["ws_ok"] = None

    def regions_of(ip):
        return [r for r in cfg["targets"] if ip in buckets.get((r, "443"), []) + buckets.get((r, "8443"), [])]

    out_data = {
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source": cfg["source"],
        "vless_uuid": VLESS_UUID,
        "vless_sni": WS_SNI,
        "layers": ["L1 latency", "L2 stability", "L3 egress-validity"] + (["L4 vless-ws-tunnel-speed"] if l4 else []),
        "L4_enabled": l4,
        "top_per_region": top_per_region,
        "alive": len(alive),
        "final": len(l3),
        "items": [
            {
                "ip": ip,
                "port": port,
                "regions": regions_of(ip),
                "avg_ms": s["avg_ms"],
                "rate": s["rate"],
                "ws_ok": s.get("ws_ok"),
                "mbps": s.get("mbps"),
            }
            for (ip, port), s in sorted(l3, key=lambda x: (-(x[1].get("mbps") or 0), x[1]["avg_ms"]))
        ],
    }
    out_data["per_region"] = {r: sum(1 for x in out_data["items"] if r in x["regions"]) for r in cfg["targets"]}
    json.dump(out_data, open(out, "w"), indent=2)
    print(f"final {len(l3)} -> {out}", flush=True)
    return out_data

if __name__ == "__main__":
    do_l4 = "--l4" in sys.argv
    args = [a for a in sys.argv[1:] if a != "--l4"]
    run(*args, l4=do_l4)
