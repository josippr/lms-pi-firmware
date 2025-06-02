# Network speedtest module
# v1.0.0
# Author: Josip Prpić
# Date: 18.04.2025

import speedtest
import datetime

def format_speed(bits_per_second):
    """Convert bits per second to Mbps with 2 decimal places."""
    return round(bits_per_second / 1_000_000, 2)

def run_speed_test():
    print("Starting network speed test...\n")

    st = speedtest.Speedtest()

    # Get best server based on ping
    print("Finding best server...")
    best = st.get_best_server()
    print(f"Found: {best['host']} located in {best['country']} (Latency: {best['latency']} ms)\n")

    # Perform download test
    print("Testing download speed...")
    download_speed = st.download()

    # Perform upload test
    print("Testing upload speed...")
    upload_speed = st.upload()

    # Get ping
    ping = st.results.ping

    # Print results
    print("\n--- Speed Test Results ---")
    print(f"Timestamp:      {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Download Speed: {format_speed(download_speed)} Mbps")
    print(f"Upload Speed:   {format_speed(upload_speed)} Mbps")
    print(f"Ping:           {ping} ms")
    print("----------------------------")

if __name__ == "__main__":
    run_speed_test()
