import socket, ipaddress, sys, threading, time, os, requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterator, List
from tqdm import tqdm
import warnings
warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

PORT_SCAN_TIMEOUT = 3.0
MAX_WORKERS_SCAN = min(500, os.cpu_count() * 50)
BATCH_SIZE_SCAN = 5000
PORT = 8888
RESULT_OPEN = "open_8888.txt"
PANEL_PATH = "/panel"
WEB_TIMEOUT = 10.0
MAX_WORKERS_WEB = min(150, os.cpu_count() * 20)
KEYWORD = "3X-UI"
RESULT_FINAL = "3xui_panel_ips.txt"
lock = threading.Lock()
open_cnt = 0
found_3xui = 0
pbar: tqdm = None
session = requests.Session()
session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
def check_port(ip: str, port: int = PORT) -> bool:
    try:
        s = socket.create_connection((ip, port), timeout=PORT_SCAN_TIMEOUT)
        s.close()
        return True
    except:
        return False
def check_panel(ip: str) -> bool:
    global found_3xui, pbar
    url = f"http://{ip}:{PORT}{PANEL_PATH}"
    try:
        r = session.get(url, timeout=WEB_TIMEOUT, verify=False)
        pbar.update(1)
        if r.status_code == 200 and KEYWORD.lower() in r.text.lower():
            line = f"{ip}:{PORT}{PANEL_PATH}\n"
            with lock:
                found_3xui += 1
                with open(RESULT_FINAL, "a", encoding="utf-8") as f:
                    f.write(line)
            pbar.write(f"[3X-UI PANEL] {ip}:{PORT}{PANEL_PATH} → {url}")
            return True
    except:
        pass
    pbar.update(1)
    return False
def ip_range_generator(start_ip: str, end_ip: str) -> Iterator[str]:
    start = int(ipaddress.IPv4Address(start_ip))
    end = int(ipaddress.IPv4Address(end_ip))
    for i in range(start, end + 1):
        yield str(ipaddress.IPv4Address(i))
def chunked(iterable, size):
    it = iter(iterable)
    while True:
        chunk = []
        try:
            for _ in range(size):
                chunk.append(next(it))
            yield chunk
        except StopIteration:
            if chunk:
                yield chunk
            break
def main():
    global pbar, open_cnt, found_3xui
    print("OTC TG群@soqunla + 3X-UI 一体化探测器")
    print("最终输出: 仅含 3X-UI 的 IP:端口\n")
    rng = input("IP范围 (如 0.0.0.0-255.255.255.255): ").strip()
    if not rng or "-" not in rng:
        print("[!] 请输入正确范围，如 1.1.1.1-2.2.2.2")
        return
    start_ip, end_ip = rng.split("-", 1)
    total_ips = int(ipaddress.IPv4Address(end_ip)) - int(ipaddress.IPv4Address(start_ip)) + 1
    open(RESULT_OPEN, "w", encoding="utf-8").write(f"# {PORT} 端口开放的 IP 列表\n")
    open(RESULT_FINAL, "w", encoding="utf-8").write(
        f"# 3X-UI 面板 ({PANEL_PATH}) 页面包含 '{KEYWORD}'\n"
        f"# 格式: IP:端口\n"
        f"# 生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
    )
    print(f"\n[步骤1] 起飞 → 扫描 {total_ips:,} 个 IP 的 {PORT} 端口\n")
    pbar = tqdm(total=total_ips, desc="扫描端口", unit="ip", ncols=90,
                bar_format="{l_bar}{bar}| {n_fmt}/{total} [{elapsed}<{remaining}, {rate_fmt}{postfix}]")

    open_ips = []
    with ThreadPoolExecutor(MAX_WORKERS_SCAN) as exe:
        batch_count = 0
        for ip_batch in chunked(ip_range_generator(start_ip, end_ip), BATCH_SIZE_SCAN):
            batch_count += 1
            futures = [exe.submit(check_port, ip) for ip in ip_batch]
            for ip, future in zip(ip_batch, as_completed(futures)):
                if future.result():
                    with lock:
                        open_cnt += 1
                        open_ips.append(ip)
                        with open(RESULT_OPEN, "a", encoding="utf-8") as f:
                            f.write(f"{ip}:{PORT}\n")
                pbar.update(1)
            print(f"[i] 第 {batch_count} 批完成，累计 {min(batch_count * BATCH_SIZE_SCAN, total_ips)} 个 IP")

    pbar.close()
    print(f"\n[步骤1 完成] 共发现 {open_cnt} 个 {PORT} 端口开放 → {RESULT_OPEN}\n")

    if open_cnt == 0:
        print("未发现开放端口，程序结束。")
        return
    print(f"[步骤2] 起飞 → 探测 {open_cnt:,} 个 IP 的 {PANEL_PATH} 页面是否含 '{KEYWORD}'\n")

    pbar = tqdm(total=open_cnt, desc="探测面板", unit="ip", ncols=90,
                bar_format="{l_bar}{bar}| {n_fmt}/{total} [{elapsed}<{remaining}, {rate_fmt}{postfix}]")

    with ThreadPoolExecutor(MAX_WORKERS_WEB) as exe:
        futures = [exe.submit(check_panel, ip) for ip in open_ips]
        for f in as_completed(futures):
            f.result()

    pbar.close()
    print(f"\n\n大功告成！共发现 {found_3xui} 个 3X-UI 面板")
    print(f"   开放端口列表 → {RESULT_OPEN}")
    print(f"   3X-UI 面板列表 → {RESULT_FINAL}")

    if found_3xui > 0:
        print(f"   示例：")
        with open(RESULT_FINAL, "r", encoding="utf-8") as f:
            for i, line in enumerate(f):
                if i >= 5: break
                if not line.startswith("#"):
                    print(f"     {line.strip()}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n已手动停止，当前进度：{open_cnt} 个开放，{found_3xui} 个 3X-UI")
        sys.exit(0)
