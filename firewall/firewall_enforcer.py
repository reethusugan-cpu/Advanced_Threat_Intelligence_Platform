import subprocess

def block_ip(ip_address):
    # Standard Step 1: Check if it's already there
    check_command = ["sudo", "iptables", "-C", "INPUT", "-s", ip_address, "-j", "DROP"]
    check_result = subprocess.run(check_command, capture_output=True, text=True)
    
    # Situation B Handler: If found, skip it!
    if check_result.returncode == 0:
        print(f"[*] SKIP: {ip_address} is already in the firewall rules. Skipping safely.")
        return

    # Situation A Handler: If not found, block it!
    print(f"[!] Target {ip_address} not found in firewall. Appending rule now...")
    block_command = ["sudo", "iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"]
    subprocess.run(block_command, capture_output=True)
    print(f"[+] SUCCESS: {ip_address} is now blocked.")

if __name__ == "__main__":
    print("=== Running Single Standard Firewall Engine ===")
    
    # A mixed list: 3 unique IPs, and then a duplicate of the first one
    incoming_threats = ["192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.1"]
    
    for ip in incoming_threats:
        block_ip(ip)