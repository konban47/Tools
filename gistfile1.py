#!/usr/bin/env python3
"""
併發請求 Google Play acquire API，最多 300 次。
urllib + ThreadPoolExecutor (穩定，不會卡)
RC=0/1 成功即停。
"""

import gzip, ssl, re, time, secrets
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Event, Lock
import urllib.request, urllib.error

FILE = "D:\[15518] request_play-fe.googleapis.com_message.txt"
URL = "https://play-fe.googleapis.com/fdfe/ees/acquire?theme=2"
MAX = 10000
CONC = 50      # 提高併發
TIMEOUT = 20

SUCCESS = {0, 1}
KNOWN = {3: "地區", 6: "服務器", 0xFF: "HTTP錯誤", 0xFE: "連線錯誤"}

stop = Event()
stats = {}
lock = Lock()
saved_rc = set()

with open(FILE, "rb") as f:
    raw = f.read()
crlf = raw.find(b"\r\n\r\n")
base = raw[crlf + 4:]

hdrs = {}
for line in raw[:crlf].decode(errors="replace").split("\r\n")[1:]:
    if ":" in line:
        k, v = line.split(":", 1)
        hdrs[k.strip().lower()] = v.strip()

ORIG_NONCE = re.search(rb"nonce=([A-Za-z0-9_\-]+)", base)
NONCE_LEN = len(ORIG_NONCE.group(1)) if ORIG_NONCE else 342

REQ_HDRS = {
    "Host": "play-fe.googleapis.com",
    "Content-Type": "application/x-protobuf",
    "User-Agent": hdrs.get("user-agent", ""),
    "Authorization": hdrs.get("authorization", ""),
    "Accept-Language": "zh-TW",
    "Accept-Encoding": "gzip, deflate, br",
    "X-PS-RH": hdrs.get("x-ps-rh", ""),
}

# 預生成 nonce pool 加速
import os as _os
NONCE_POOL = [secrets.token_urlsafe(256).encode() for _ in range(MAX)]

print(f"Body: {len(base)}B | Concurrency: {CONC} | Max: {MAX}")
print(f"Success: RC in {SUCCESS}")
print("=" * 60)

def send(idx):
    if stop.is_set():
        return idx, None, None

    body = base.replace(ORIG_NONCE.group(1), NONCE_POOL[idx % MAX])

    try:
        ctx = ssl.create_default_context()
        req = urllib.request.Request(URL, data=body, headers=REQ_HDRS, method="POST")
        resp = urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx)
        data = resp.read()
        if "gzip" in resp.getheader("Content-Encoding", ""):
            data = gzip.decompress(data)
        m = re.search(rb'RESPONSE_CODE.([\x00-\x08])', data)
        rc = m.group(1)[0] if m else None
        return idx, rc, data
    except urllib.error.HTTPError as e:
        err = e.read()
        try: err = gzip.decompress(err)
        except: pass
        return idx, 0xFF, err
    except Exception as e:
        return idx, 0xFE, None

t0 = time.time()
done = 0
last = t0

with ThreadPoolExecutor(max_workers=CONC) as ex:
    futs = {}
    for i in range(min(CONC * 2, MAX)):
        futs[ex.submit(send, i)] = i
    next_i = len(futs)

    while futs and not stop.is_set():
        done_set = as_completed(futs)
        for fut in done_set:
            idx = futs.pop(fut)
            idx, rc, data = fut.result()
            done += 1

            with lock:
                stats[rc] = stats.get(rc, 0) + 1

            if rc is not None and rc in SUCCESS:
                stop.set()
                out = f"/home/luminet/coding/fg/success_{idx}.bin"
                with open(out, "wb") as f:
                    f.write(data)
                t = time.time() - t0
                print(f"\n{'='*60}")
                print(f"🏆 成功! #{idx} RC={rc} | {done}次 {t:.1f}s {done/t:.0f}r/s")
                print(f"{'='*60}")
                break

            now = time.time()
            if rc is not None and rc not in SUCCESS and rc not in KNOWN and rc not in saved_rc:
                saved_rc.add(rc)
                msg = ""
                if data:
                    m = re.search(rb'(Server error|Error|DEBUG_MESSAGE)[^\"]{0,50}', data)
                    if m: msg = m.group(0).decode(errors='replace')[:60]
                print(f"  🔔 新RC={rc}! #{idx}: {msg}")

            if done % 20 == 0 or now - last > 3:
                last = now
                t = time.time() - t0
                labels = " ".join([f"RC{k}={v}" for k,v in sorted(stats.items())])
                print(f"  [{done:3d}/{MAX}] #{idx} RC={rc} | {done/t:.1f}r/s | {labels}")

            if stop.is_set():
                break

            if next_i < MAX:
                futs[ex.submit(send, next_i)] = next_i
                next_i += 1

        if stop.is_set():
            break

for fut in futs:
    fut.cancel()

t = time.time() - t0
print(f"\n完成: {done}次 | {t:.1f}s | {done/t:.1f} r/s")
print(f"統計: {dict(sorted(stats.items()))}")
print("🏆 成功!" if stop.is_set() else "❌ 無成功")