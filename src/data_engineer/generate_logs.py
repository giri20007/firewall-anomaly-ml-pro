import random
import csv
import os

# Ensure the output directory matches your repository structure
OUTPUT_DIR = os.path.join("data", "raw")
os.makedirs(OUTPUT_DIR, exist_ok=True)
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "raw_simulated_firewall_logs.csv")

def generate_ip():
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.0/24"

def generate_synthetic_rules(num_rules=50):
    protocols = ['TCP', 'UDP', 'ICMP', 'ANY']
    actions = ['ALLOW', 'DENY']
    rules = []

    for i in range(num_rules):
        rule = {
            'Rule_ID': i + 1,
            'Action': random.choice(actions),
            'Protocol': random.choice(protocols),
            'Source_IP': generate_ip(),
            'Dest_IP': generate_ip(),
            'Dest_Port': random.choice([80, 443, 22, 21, 3389, 'ANY'])
        }
        rules.append(rule)
        
    # --- INJECTING INTENTIONAL ANOMALIES FOR THE AI TO FIND ---
    
    # 1. Shadowing Anomaly (Rule 5 completely covers/shadows Rule 6)
    rules[4] = {'Rule_ID': 5, 'Action': 'ALLOW', 'Protocol': 'ANY', 'Source_IP': '192.168.1.0/24', 'Dest_IP': 'ANY', 'Dest_Port': 'ANY'}
    rules[5] = {'Rule_ID': 6, 'Action': 'DENY', 'Protocol': 'TCP', 'Source_IP': '192.168.1.0/24', 'Dest_IP': '10.0.0.5/32', 'Dest_Port': 80}
    
    # 2. Redundancy Anomaly (Rule 10 and 11 are exact duplicates)
    redundant_rule = {'Rule_ID': 10, 'Action': 'DENY', 'Protocol': 'TCP', 'Source_IP': '172.16.0.0/16', 'Dest_IP': 'ANY', 'Dest_Port': 22}
    rules[9] = redundant_rule
    rules[10] = {'Rule_ID': 11, 'Action': 'DENY', 'Protocol': 'TCP', 'Source_IP': '172.16.0.0/16', 'Dest_IP': 'ANY', 'Dest_Port': 22}

    # 3. Conflict Anomaly (Rule 15 and 16 target identical traffic but have opposite actions)
    rules[14] = {'Rule_ID': 15, 'Action': 'ALLOW', 'Protocol': 'UDP', 'Source_IP': '10.10.10.0/24', 'Dest_IP': '20.20.20.0/24', 'Dest_Port': 443}
    rules[15] = {'Rule_ID': 16, 'Action': 'DENY', 'Protocol': 'UDP', 'Source_IP': '10.10.10.0/24', 'Dest_IP': '20.20.20.0/24', 'Dest_Port': 443}

    return rules

def main():
    print("Generating simulated firewall rules...")
    rules = generate_synthetic_rules(50)
    
    with open(OUTPUT_FILE, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=rules[0].keys())
        writer.writeheader()
        writer.writerows(rules)
        
    print(f"Success! Saved dataset to: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()

