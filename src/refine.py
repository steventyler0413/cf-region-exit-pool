"""Deep refine: L1 latency, L2 stability (N conns), L3 egress-validity.
L4 (real speed via SOCKS/HTTP-CONNECT) runs only on GitHub runner (clean egress);
flag it here but skip when running locally.
"""
import zipfile, io, json, time, socket, urllib.request, ipaddress, sys
from concurrent.futures import ThreadPoolExecutor

def fetch_zip(url, timeout=180):
    req = urllib.request.Request(url, headers={"User-Agent":"Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()

def build_buckets(zip_bytes, targets, ports):
    z = zipfile.ZipFile(io.BytesIO(zip_bytes))
    buckets = {(r,p): [] for r in targets for p in ports}
    for fn in z.namelist():
        if not fn.endswith(".txt"): continue
        parts = fn.split("/"); port = parts[0]; region = parts[-1].replace(".txt","")
        if region not in targets or port not in ports: continue
        for ip in [l.strip() for l in z.read(fn).decode(errors="replace").splitlines() if l.strip()]:
            buckets[(region,port)].append(ip)
    return buckets

def stable_probe(ip, port, attempts=3, timeout=2):
    """L1+L2: avg latency + success rate over N tries."""
    lats = []
    for _ in range(attempts):
        t0 = time.time()
        s = socket.socket(); s.settimeout(timeout)
        try:
            ok = s.connect_ex((ip, int(port))) == 0
        except Exception:
            ok = False
        finally:
            s.close()
        if ok:
            lats.append((time.time()-t0)*1000)
        time.sleep(0.05)
    if not lats:
        return None
    return {"avg_ms": round(sum(lats)/len(lats),1), "rate": round(len(lats)/attempts,2)}

def l3_egress_valid(ip):
    """L3: is this a global, routable, non-private IP (i.e. a real egress)."""
    try:
        a = ipaddress.ip_address(ip)
        return a.is_global and not a.is_private and not a.is_loopback
    except ValueError:
        return False

def l4_speed_via_socks(ip, port, timeout=6):
    """L4: download a small payload through ip:port as SOCKS5, return MB/s (0 if fails).
    Only meaningful on a clean runner; 22's egress is America-biased + many 103.x are not SOCKS proxies,
    so this returns 0 locally. Enabled only when L4_enabled_in_workflow."""
    import socks, ssl
    try:
        proxy = socks.socksocket(socks.PROXY_TYPE_SOCKS5, None, None, True)
        proxy.set_proxy(ip, int(port))
        proxy.settimeout(timeout)
        s = proxy.create_connection(("speed.cloudflare.com",443), timeout=timeout)
        ctx = ssl.create_default_context()
        w = ctx.wrap_socket(s, server_hostname="speed.cloudflare.com")
        w.sendall(b"GET /__down?bytes=300000 HTTP/1.1\r\nHost: speed.cloudflare.com\r\nConnection: close\r\n\r\n")
        t0 = time.time(); got = 0
        try:
            while got < 300000:
                chunk = w.recv(65536)
                if not chunk: break
                got += len(chunk)
        except Exception:
            pass
        dt = time.time()-t0
        w.close(); s.close()
        return round(got*8/1e6/max(dt,0.001),1) if got > 0 else 0.0
    except Exception:
        return 0.0

def run(config_path="config.json", out="data/refined.json", l4=False):
    cfg = json.load(open(config_path))
    zip_bytes = fetch_zip(cfg["source"])
    buckets = build_buckets(zip_bytes, cfg["targets"], cfg["refine_ports"])
    tasks = set()
    for (r,p), ips in buckets.items():
        for ip in ips:
            tasks.add((ip,p))
    all_tasks = list(tasks)
    print(f"refining {len(all_tasks)} (ip,port)", flush=True)

    t0 = time.time()
    with ThreadPoolExecutor(max_workers=cfg.get("max_workers",128)) as ex:
        futs = {t: ex.submit(stable_probe, t[0], t[1], cfg.get("attempts",3), cfg.get("timeout_s",2)) for t in all_tasks}
        stats = {t: fut.result() for t,fut in futs.items()}
    alive = [(t,s) for t,s in stats.items() if s]
    print(f"L1/L2 alive: {len(alive)} ({time.time()-t0:.0f}s)", flush=True)

    l3 = [(t,s) for t,s in alive if l3_egress_valid(t[0])]
    print(f"L3 egress-valid: {len(l3)}", flush=True)

    if l4:
        top = [t for t,_ in sorted(l3, key=lambda x:x[1]["avg_ms"])[:cfg.get("top_for_L4",150)]]
        tv = time.time()
        with ThreadPoolExecutor(max_workers=32) as ex:
            sp = {task: ex.submit(l4_speed_via_socks, task[0], task[1]) for task in top}
        for task, stat in l3:
            if task in sp:
                stat["mbps"] = sp[task].result()
        l3 = [(t,s) for t,s in l3 if s.get("mbps",0) >= 1.0]
        print(f"L4 >=1Mbps: {len(l3)} in {time.time()-tv:.0f}s", flush=True)
    else:
        for _,s in l3:
            s["mbps"] = None

    def regions_of(ip):
        return [r for r in cfg["targets"] if ip in buckets.get((r,"443"),[])+buckets.get((r,"8443"),[])]
    out_data = {
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source": cfg["source"],
        "layers": ["L1 latency","L2 stability","L3 egress-validity"] + (["L4 speed"] if l4 else []),
        "L4_enabled": l4,
        "alive": len(alive), "final": len(l3),
        # per_region computed from items (below, after build)
        "items": [
            {"ip":ip,"port":port,"regions":regions_of(ip),
             "avg_ms":s["avg_ms"],"rate":s["rate"],"mbps":s.get("mbps")}
            for (ip,port),s in sorted(l3, key=lambda x:x[1]["avg_ms"])
        ],
    }
    out_data["per_region"] = {r: sum(1 for x in out_data["items"] if r in x["regions"]) for r in cfg["targets"]}
    json.dump(out_data, open(out,"w"), indent=2)
    print(f"final {len(l3)} -> {out}", flush=True)
    return out_data

if __name__ == "__main__":
    do_l4 = "--l4" in sys.argv
    args = [a for a in sys.argv[1:] if a != "--l4"]
    run(*args, l4=do_l4)
