import subprocess
import re
import json

def get_arp_table():
    # Run the arp -a command
    result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
    print(result.stdout)  # Print the ARP table
    return result.stdout

def parse_arp_table(arp_output):
    # Regular expression to match IP and MAC addresses
    arp_regex = re.compile(r'(\d+\.\d+\.\d+\.\d+)\s+([\w-]+)\s+([\w:]+)')
    arp_entries = arp_regex.findall(arp_output)
    return arp_entries

def check_for_arp_poisoning(arp_entries):
    ip_mac_map = {}
    arp_poisoning_detected = False
    for ip, _, mac in arp_entries:
        if ip in ip_mac_map:
            if ip_mac_map[ip] != mac:
                print(f"Warning: Potential ARP poisoning detected for IP {ip}!")
                print(f"MAC addresses: {ip_mac_map[ip]} and {mac}")
                arp_poisoning_detected = True
        else:
            ip_mac_map[ip] = mac

    # Save the ip_mac_map to a JSON file
    with open('ip_mac_map.json', 'w') as json_file:
        json.dump(ip_mac_map, json_file, indent=4)

    if not arp_poisoning_detected:
        print("No ARP poisoning detected.")

if __name__ == "__main__":
    arp_output = get_arp_table()
    arp_entries = parse_arp_table(arp_output)
    check_for_arp_poisoning(arp_entries)
