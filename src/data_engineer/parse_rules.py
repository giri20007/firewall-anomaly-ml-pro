import os
import csv
import ipaddress

# Define exact relative paths from project root
RAW_FILE_PATH = os.path.join("data", "raw", "raw_simulated_firewall_logs.csv")
PROCESSED_DIR = os.path.join("data", "processed")
PROCESSED_FILE_PATH = os.path.join(PROCESSED_DIR, "encoded_firewall_rules.csv")

def ip_to_numerical(ip_str):
    """Converts an IP CIDR string or 'ANY' into (IP_integer, mask_prefix)."""
    if ip_str.upper() == 'ANY':
        return 0, 0
    try:
        network = ipaddress.ip_network(ip_str, strict=False)
        return int(network.network_address), network.prefixlen
    except ValueError:
        return 0, 0

def encode_protocol(proto_str):
    """Maps protocol strings to discrete integer tokens."""
    mapping = {'ANY': 0, 'TCP': 1, 'UDP': 2, 'ICMP': 3}
    return mapping.get(proto_str.upper(), 0)

def encode_action(action_str):
    """Maps action strings to binary tokens (ALLOW=1, DENY=0)."""
    return 1 if action_str.upper() == 'ALLOW' else 0

def encode_port(port_str):
    """Converts port string to integer, mapping 'ANY' to 0."""
    if port_str.upper() == 'ANY':
        return 0
    return int(port_str)

def parse_and_encode():
    """Reads raw text rules, processes them to vectors, and saves them."""
    os.makedirs(PROCESSED_DIR, exist_ok=True)
    
    # Check if raw file exists where expected
    if not os.path.exists(RAW_FILE_PATH):
        print(f"Error: Raw file not found at {RAW_FILE_PATH}. Try running generate_logs.py from the root folder.")
        return

    encoded_rules = []
    
    print(f"Reading raw logs from: {RAW_FILE_PATH}")
    with open(RAW_FILE_PATH, mode='r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            src_ip_int, src_mask = ip_to_numerical(row['Source_IP'])
            dst_ip_int, dst_mask = ip_to_numerical(row['Dest_IP'])
            
            encoded_rule = {
                'Rule_ID': int(row['Rule_ID']),
                'Action': encode_action(row['Action']),
                'Protocol': encode_protocol(row['Protocol']),
                'Source_IP_Int': src_ip_int,
                'Source_Mask': src_mask,
                'Dest_IP_Int': dst_ip_int,
                'Dest_Mask': dst_mask,
                'Dest_Port': encode_port(row['Dest_Port'])
            }
            encoded_rules.append(encoded_rule)
            
    # Save the processed matrix back as a CSV for inspection
    with open(PROCESSED_FILE_PATH, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=encoded_rules[0].keys())
        writer.writeheader()
        writer.writerows(encoded_rules)
        
    print(f"Success! Matrix encoded and saved to: {PROCESSED_FILE_PATH}")

if __name__ == "__main__":
    parse_and_encode()

