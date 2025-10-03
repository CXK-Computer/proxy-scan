import asyncio
import json
import os
import sys
import time
import csv
import aiohttp
from tqdm.asyncio import tqdm

CONFIG = {
    "api_base": "https://check.socks5.cmliussss.net/check",
    "token": "",
    "concurrency": 2000,
    "timeout": 8,
    "proxy_mode": "http",  # http 或 socks5
    "outdir": "api_output",
    "chunk_size": 10000,  # 每批写入条数
    "start_line": 0,       # 分布式运行：起始行
    "end_line": None       # 分布式运行：结束行(None 表示到文件末尾)
}

async def fetch_check(session: aiohttp.ClientSession, api_base: str, proxy_str: str, extra_params: dict = None, timeout: int = 8):
    params = {}
    if extra_params:
        params.update(extra_params)
    params['proxy'] = proxy_str
    try:
        async with session.get(api_base, params=params, timeout=timeout) as resp:
            try:
                data = await resp.json(content_type=None)
            except Exception:
                data = {"_raw": await resp.text(), "_status": resp.status}
            success = bool(isinstance(data, dict) and (data.get("success") is True or data.get("status") == "ok" or 200 <= resp.status < 300))
            return proxy_str, success, data
    except Exception as e:
        return proxy_str, False, {"error": str(e)}

async def run_batch(proxies, api_base, concurrency, timeout, extra_params):
    sem = asyncio.Semaphore(concurrency)
    results = []
    timeout_cfg = aiohttp.ClientTimeout(total=None, sock_connect=timeout, sock_read=timeout)
    async with aiohttp.ClientSession(timeout=timeout_cfg, headers={"User-Agent": "checker/1.0"}) as session:
        async def worker(p):
            async with sem:
                proxy_str, ok, data = await fetch_check(session, api_base, p, extra_params, timeout)
                if ok:
                    results.append((proxy_str, ok, data))
        tasks = [asyncio.create_task(worker(p)) for p in proxies]
        with tqdm(total=len(tasks), desc="Checking", unit="proxy") as pbar:
            for f in asyncio.as_completed(tasks):
                await f
                pbar.update(1)
    return results

# ---------------- 辅助 -----------------

def normalize_proxy_line(line: str, mode: str):
    ln = line.strip()
    if not ln:
        return None
    if "://" not in ln:
        return f"{mode}://{ln}"
    else:
        if not ln.lower().startswith(mode+"://"):
            return f"{mode}://{ln.split('//',1)[1]}"
        return ln

def parse_asn_and_dc(data: dict):
    asn_raw = data.get('asn') if isinstance(data, dict) else {}
    asn = asn_raw if isinstance(asn_raw, dict) else {}
    dc = data.get('datacenter') if isinstance(data.get('datacenter'), dict) else {}
    return {
        'asn': asn.get('asn'),
        'abuser_score': asn.get('abuser_score') or (data.get('abuse') and data.get('abuse').get('score')),
        'route': asn.get('route'),
        'org': asn.get('org') or asn.get('descr'),
        'country': (asn.get('country') or data.get('location', {}).get('country') or '').upper(),
        'ip_type': '数据中心' if dc else (asn.get('type') or ''),
        'datacenter': dc,
    }

def write_chunk(outdir, chunk_id, results, mode):
    os.makedirs(outdir, exist_ok=True)
    txt_path = os.path.join(outdir, f"working_part{chunk_id}.txt")
    csv_path = os.path.join(outdir, f"details_part{chunk_id}.csv")
    # TXT
    with open(txt_path, "w", encoding="utf-8") as f:
        for proxy, ok, data in results:
            f.write(proxy + "\n")
    # CSV
    fields = ["proxy","mode","ip","asn","abuser_score","route","org","country","ip_type","datacenter_name","datacenter_domain","datacenter_network"]
    with open(csv_path, "w", newline='', encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for proxy, ok, data in results:
            parsed = parse_asn_and_dc(data)
            dc = parsed.get('datacenter') or {}
            writer.writerow({
                "proxy": proxy,
                "mode": mode,
                "ip": data.get('ip'),
                "asn": parsed.get('asn'),
                "abuser_score": parsed.get('abuser_score'),
                "route": parsed.get('route'),
                "org": parsed.get('org'),
                "country": parsed.get('country'),
                "ip_type": parsed.get('ip_type'),
                "datacenter_name": dc.get('datacenter'),
                "datacenter_domain": dc.get('domain'),
                "datacenter_network": dc.get('network'),
            })
    print(f"已保存 {len(results)} 条 -> {txt_path}, {csv_path}")

# ---------------- 主逻辑 -----------------

def process_large_file(file_path):
    start, end = CONFIG['start_line'], CONFIG['end_line']
    chunk_size = CONFIG['chunk_size']
    api_base = CONFIG['api_base']
    extra = {"token": CONFIG['token']} if CONFIG['token'] else {}

    chunk_id = 1
    buffer = []
    processed = 0

    with open(file_path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f):
            if i < start:
                continue
            if end and i >= end:
                break
            proxy = normalize_proxy_line(line, CONFIG['proxy_mode'])
            if proxy:
                buffer.append(proxy)
            if len(buffer) >= chunk_size:
                results = asyncio.run(run_batch(buffer, api_base, CONFIG['concurrency'], CONFIG['timeout'], extra))
                write_chunk(CONFIG['outdir'], chunk_id, results, CONFIG['proxy_mode'])
                buffer.clear()
                chunk_id += 1
            processed += 1
    if buffer:
        results = asyncio.run(run_batch(buffer, api_base, CONFIG['concurrency'], CONFIG['timeout'], extra))
        write_chunk(CONFIG['outdir'], chunk_id, results, CONFIG['proxy_mode'])
    print(f"处理完成，总 {processed} 条")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("用法: python interactive_proxy_checker.py proxies.txt")
        sys.exit(1)
    file_path = sys.argv[1]
    process_large_file(file_path)
