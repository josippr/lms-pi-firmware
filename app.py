import subprocess
import threading
import time

# import scripts
SCRIPTS = {
    # "network-scanner": "/network-scanner/scanner.py",
    # "network-speedtest": "/network-speedtest/speedtest.py",
    "node-metrics": "./node-metrics/send_metrics.py",
    "intrusion-detection": "./intrusion-detection/intrusion.py",
    "fritzbox-plugin": "./fritzbox-plugin/fritzbox.py",
    "network-status": "./network-status/network-status.py",
    "network-analysis": "./network-analysis/networkAnalysis.py"
}

# Run script (crash safe)
def run_script(path):
    def target():
        while True:
            try:
                print(f"[INFO] Running script: {path}")
                subprocess.run(["./venv/bin/python", path], check=True)
            except subprocess.CalledProcessError as e:
                print(f"[ERROR] Script {path} failed: {e}")
            # Wait 5 minutes before next run regardless of success/failure
            print("[INFO] Waiting for 5 minutes before next run...")
            time.sleep(300)
    t = threading.Thread(target=target)
    t.start()
    return t


def main():
    print("[INFO] Starting Pi services...")
    
    # TODO: t2, t3 will be enabled when APIs are ready
    # run scripts
    # t2 = run_script(SCRIPTS["network-scanner"])
    # t3 = run_script(SCRIPTS["network-speedtest"])
    t4 = run_script(SCRIPTS["node-metrics"])
    t5 = run_script(SCRIPTS["network-analysis"])
    t6 = run_script(SCRIPTS["intrusion-detection"])
    t7 = run_script(SCRIPTS["fritzbox-plugin"])
    t8 = run_script(SCRIPTS["network-status"])

    try:
        # Main thread, run every 5 minutes
        while True:
            time.sleep(300)
    except KeyboardInterrupt:
        print("[INFO] Shutting down...")

if __name__ == "__main__":
    main()