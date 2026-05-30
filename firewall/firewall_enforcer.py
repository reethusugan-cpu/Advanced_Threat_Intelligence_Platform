import subprocess #subprocess allows Python to execute Linux terminal commands.


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

    print(
        f"[+] SUCCESS: {ip_address} blocked."
    )