import os
import csv
import json

PROCESSED_FILE_PATH = os.path.join("data", "processed", "encoded_firewall_rules.csv")
REPORT_DIR = os.path.join("data", "reports")
REPORT_FILE_PATH = os.path.join(REPORT_DIR, "anomaly_report.json")

def is_encompassing(val_a, val_b):
    """Checks if Rule A's port/protocol (val_a) encompasses Rule B's (val_b). 0 means ANY."""
    return val_a == 0 or val_a == val_b

def ip_encompasses(ip_int_a, mask_a, ip_int_b, mask_b):
    """
    Checks if IP Range A completely encompasses IP Range B.
    If A is 0/0 (ANY), it encompasses everything.
    Otherwise, A must have a smaller or equal mask (broader network) and identical base IP integer.
    """
    if ip_int_a == 0 and mask_a == 0:
        return True
    return (ip_int_a == ip_int_b) and (mask_a <= mask_b)

def detect_anomalies():
    """Scans the processed mathematical matrix for rule anomalies."""
    if not os.path.exists(PROCESSED_FILE_PATH):
        print(f"Error: Processed file not found at {PROCESSED_FILE_PATH}")
        return

    # Ensure reports directory exists
    os.makedirs(REPORT_DIR, exist_ok=True)

    rules = []
    with open(PROCESSED_FILE_PATH, mode='r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            # Convert string matrix back to integers for logical comparison
            rules.append({k: int(v) for k, v in row.items()})

    anomalies = {
        "shadowing": [],
        "redundancy": [],
        "conflicts": []
    }

    # Compare every rule (Rule A) against every rule beneath it (Rule B)
    for i in range(len(rules)):
        rule_a = rules[i]
        
        for j in range(i + 1, len(rules)):
            rule_b = rules[j]
            
            # 1. Check for exact match in conditions (IPs, Ports, Protocol)
            exact_match = (
                rule_a['Source_IP_Int'] == rule_b['Source_IP_Int'] and
                rule_a['Source_Mask'] == rule_b['Source_Mask'] and
                rule_a['Dest_IP_Int'] == rule_b['Dest_IP_Int'] and
                rule_a['Dest_Mask'] == rule_b['Dest_Mask'] and
                rule_a['Protocol'] == rule_b['Protocol'] and
                rule_a['Dest_Port'] == rule_b['Dest_Port']
            )

            if exact_match:
                if rule_a['Action'] == rule_b['Action']:
                    anomalies["redundancy"].append(f"Rule {rule_b['Rule_ID']} is redundant to Rule {rule_a['Rule_ID']}")
                else:
                    anomalies["conflicts"].append(f"Rule {rule_a['Rule_ID']} and Rule {rule_b['Rule_ID']} conflict (opposite actions)")
                continue # Skip to next rule B, already flagged

            # 2. Check for Shadowing (Rule A completely covers Rule B)
            shadows_protocol = is_encompassing(rule_a['Protocol'], rule_b['Protocol'])
            shadows_port = is_encompassing(rule_a['Dest_Port'], rule_b['Dest_Port'])
            shadows_src = ip_encompasses(rule_a['Source_IP_Int'], rule_a['Source_Mask'], rule_b['Source_IP_Int'], rule_b['Source_Mask'])
            shadows_dest = ip_encompasses(rule_a['Dest_IP_Int'], rule_a['Dest_Mask'], rule_b['Dest_IP_Int'], rule_b['Dest_Mask'])

            if shadows_protocol and shadows_port and shadows_src and shadows_dest:
                anomalies["shadowing"].append(
                    f"Rule {rule_a['Rule_ID']} shadows Rule {rule_b['Rule_ID']} (Rule {rule_b['Rule_ID']} is unreachable)"
                )

    # Save the findings to a JSON report
    with open(REPORT_FILE_PATH, 'w') as json_file:
        json.dump(anomalies, json_file, indent=4)

    print(f"Anomaly scan complete! Found:")
    print(f"- {len(anomalies['shadowing'])} Shadowed rules")
    print(f"- {len(anomalies['redundancy'])} Redundant rules")
    print(f"- {len(anomalies['conflicts'])} Conflicting rules")
    print(f"Detailed report saved to: {REPORT_FILE_PATH}")

if __name__ == "__main__":
    detect_anomalies()

