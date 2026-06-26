from scapy.all import ARP, Ether, srp
import socket
import pandas as pd
from datetime import datetime
import time
import subprocess


# Function to automatically detect network range
def get_network_range():

    output = subprocess.check_output(
        ["ip", "route"]
    ).decode()

    for line in output.splitlines():

        if "/24" in line and "src" in line:
            return line.split()[0]

    return "192.168.1.0/24"


# Device Detection Function
def detect_device(open_ports):

    if 9100 in open_ports:
        return "Printer"

    elif 554 in open_ports:
        return "CCTV Camera"

    elif 3389 in open_ports:
        return "Windows PC"

    elif 3306 in open_ports:
        return "Database Server"

    elif 22 in open_ports:
        return "Linux Machine"

    elif 80 in open_ports or 443 in open_ports:
        return "Router/Web Server"

    else:
        return "Unknown Device"


# Scan Start Time
scan_start = time.time()
start_time = datetime.now()

print("\n" + "=" * 60)
print(" NETWORK SCANNER")
print("=" * 60)

# Automatically Detect Network
target_ip = get_network_range()

print(f"\nNetwork Detected : {target_ip}")
print("\nDiscovering Devices...\n")

# Common Ports Only
ports_to_scan = [
    21, 22, 23, 25, 53,
    80, 110, 143, 443,
    445, 587, 993, 995,
    3306, 3389, 8080
]

# ARP Scan
arp = ARP(pdst=target_ip)
ether = Ether(dst="ff:ff:ff:ff:ff:ff")

packet = ether / arp

result = srp(
    packet,
    timeout=3,
    verbose=False
)[0]

data = []

total_devices = 0

# Scan Devices
for sent, received in result:

    total_devices += 1

    ip = received.psrc
    mac = received.hwsrc

    open_ports = []

    for port in ports_to_scan:

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(0.2)

        scan_result = sock.connect_ex(
            (ip, port)
        )

        if scan_result == 0:
            open_ports.append(port)

        sock.close()

    device_type = detect_device(open_ports)

    if not open_ports:
        open_ports_display = "No Open Ports Found"
    else:
        open_ports_display = ", ".join(
            map(str, open_ports)
        )

    print("\n" + "-" * 60)
    print(f"Device Number     : {total_devices}")
    print(f"IP Address        : {ip}")
    print(f"MAC Address       : {mac}")
    print(f"Open Ports        : {open_ports_display}")
    print(f"Total Open Ports  : {len(open_ports)}")
    print(f"Device Type       : {device_type}")

    data.append({
        "IP Address": ip,
        "MAC Address": mac,
        "Open Ports": open_ports_display,
        "Total Open Ports": len(open_ports),
        "Device Type": device_type
    })

# CSV Report
df = pd.DataFrame(data)

df.to_csv(
    "network_report.csv",
    index=False
)

# End Time
scan_end = time.time()
end_time = datetime.now()

duration = round(
    scan_end - scan_start,
    2
)

# TXT Report
with open(
    "network_report.txt",
    "w"
) as file:

    file.write(
        " NETWORK SCANNER REPORT\n"
    )

    file.write(
        "=" * 60 + "\n"
    )

    file.write(
        f"Scan Started : {start_time}\n"
    )

    file.write(
        f"Scan Ended   : {end_time}\n"
    )

    file.write(
        f"Duration     : {duration} seconds\n"
    )

    file.write(
        f"Devices Found: {total_devices}\n\n"
    )

    for row in data:

        file.write(
            f"IP Address        : {row['IP Address']}\n"
        )

        file.write(
            f"MAC Address       : {row['MAC Address']}\n"
        )

        file.write(
            f"Open Ports        : {row['Open Ports']}\n"
        )

        file.write(
            f"Total Open Ports  : {row['Total Open Ports']}\n"
        )

        file.write(
            f"Device Type       : {row['Device Type']}\n"
        )

        file.write(
            "-" * 60 + "\n"
        )

# Final Summary
print("\n" + "=" * 60)
print("SCAN SUMMARY")
print("=" * 60)

print(f"Total Devices Found : {total_devices}")
print(f"Scan Started        : {start_time}")
print(f"Scan Ended          : {end_time}")
print(f"Duration            : {duration} seconds")

print("\nCSV Report Saved as network_report.csv")
print("TXT Report Saved as network_report.txt")

print("\nThank you for using  Network Scanner!")
print("=" * 60)
