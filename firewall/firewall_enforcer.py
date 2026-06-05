import subprocess
import time
import sys
import os

# Dynamically inject the root project folder into Python's search paths
sys.path.insert(
    0,
    os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    )
)

def block_ip(ip_address):
    check_command = [
        "sudo",
        "iptables",
        "-C",
        "INPUT",
        "-s",
        ip_address,
        "-j",
        "DROP"
    ]

    check_result = subprocess.run(
        check_command,
        capture_output=True,
        text=True
    )

    if check_result.returncode == 0:

        print(
            f"[*] SKIP: {ip_address} already blocked."
        )

        return

    print(
        f"[!] Blocking IP : {ip_address}"
    )

    block_command = [
        "sudo",
        "iptables",
        "-A",
        "INPUT",
        "-s",
        ip_address,
        "-j",
        "DROP"
    ]

    subprocess.run(
        block_command,
        capture_output=True
    )

    print(f"[+] SUCCESS: {ip_address} blocked.")

if __name__ == "__main__":
    print("=== Starting Firewall Automation Daemon (Live Continuous Mode) ===")
    print("[+] Initialization complete. Engine is now tracking live inputs...")
    
    # MOVING THE IMPORT HERE BREAKS THE CIRCULAR DEPENDENCY COMPLETELY:
    from week3.reader import main as run_database_sync
    
    while True:
        try:
            run_database_sync()
        except Exception as e:
            print(f"[-] Integration execution error: {e}")
        
        time.sleep(60)
