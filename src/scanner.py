"""Fast scanner: pull zip.cm.edu.kg, probe 4 targets x all ports for alive+latency."""
import zipfile, io, json, time, socket, urllib.request, sys
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

def probe(ip, port, timeout=2):
    s = socket.socket(); s.settimeout(timeout)
    try:
        ok = s.connect_ex((ip, int(port))) == 0
    except Exception:
        ok = False
    finally:
        s.close()
    return (ip, port, ok)

def run(config_path="config.json", out="data/scan.json"):
    cfg = json.load(open(config_path))
    zip_bytes = fetch_zip(cfg["source"])
    buckets = build_buckets(zip_bytes, cfg["targets"], cfg["probe_ports"])

    tasks = set()
    for (r,p), ips in buckets.items():
        for ip in ips:
            tasks.add((ip, p))
    all_tasks = list(tasks)
    print(f"probing {len(all_tasks)} unique (ip,port)", flush=True)

    results = []
    with ThreadPoolExecutor(max_workers=cfg.get("max_workers",128)) as ex:
        for ip, port, ok in ex.map(lambda t: probe(t[0], t[1], cfg.get("timeout_s",2)), all_tasks):
            if ok:
                results.append({"ip":ip, "port":port})
    # attach regions
    for x in results:
        ip = x["ip"]
        x["regions"] = [r for r in cfg["targets"] if ip in buckets.get((r,x["port"]),[])]
    out_data = {
        "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "alive": len(results),
        "per_region": {r: sum(1 for x in results if r in x.get("regions",[])) for r in cfg["targets"]},
        "items": results,
    }
    json.dump(out_data, open(out, "w"), indent=2)
    print(f"alive {len(results)} -> {out}", flush=True)
    return out_data

if __name__ == "__main__":
    run(*sys.argv[1:])
