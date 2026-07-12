import os
import csv
import random

KAGGLE_FILE = os.path.join("data", "raw", "log2.csv")
OUTPUT_FILE = os.path.join("data", "raw", "raw_simulated_firewall_logs.csv")

def generate_ip():
    return f"{random.randint(10, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.0/24"

def adapt_kaggle_data():
    if not os.path.exists(KAGGLE_FILE):
        print(f"Error: Kaggle dataset not found at {KAGGLE_FILE}")
        return

    adapted_rules = []
    
    with open(KAGGLE_FILE, mode='r') as file:
        reader = csv.DictReader(file)
        
        # We will only pull the first 100 real rules so the GA runs fast
        for i, row in enumerate(reader):
            if i >= 100:
                break
                
            # Map Kaggle's 4 actions to standard binary firewall actions
            action = "ALLOW" if row['Action'].lower() == 'allow' else "DENY"
            
            rule = {
                'Rule_ID': i + 1,
                'Action': action,
                'Protocol': random.choice(['TCP', 'UDP', 'ICMP', 'ANY']),
                'Source_IP': generate_ip(),
                'Dest_IP': generate_ip(),
                'Dest_Port': row['Destination Port']
            }
            adapted_rules.append(rule)

    # --- INJECT OUR ANOMALIES FOR THE RL AGENT TO CLEAN ---
    # 1. Shadowing Anomaly
    adapted_rules[4] = {'Rule_ID': 5, 'Action': 'ALLOW', 'Protocol': 'ANY', 'Source_IP': '192.168.1.0/24', 'Dest_IP': 'ANY', 'Dest_Port': 'ANY'}
    adapted_rules[5] = {'Rule_ID': 6, 'Action': 'DENY', 'Protocol': 'TCP', 'Source_IP': '192.168.1.0/24', 'Dest_IP': '10.0.0.5/32', 'Dest_Port': 80}
    
    # 2. Redundancy Anomaly
    redundant_rule = {'Rule_ID': 10, 'Action': 'DENY', 'Protocol': 'TCP', 'Source_IP': '172.16.0.0/16', 'Dest_IP': 'ANY', 'Dest_Port': 22}
    adapted_rules[9] = redundant_rule
    adapted_rules[10] = {'Rule_ID': 11, 'Action': 'DENY', 'Protocol': 'TCP', 'Source_IP': '172.16.0.0/16', 'Dest_IP': 'ANY', 'Dest_Port': 22}

    # 3. Conflict Anomaly
    adapted_rules[14] = {'Rule_ID': 15, 'Action': 'ALLOW', 'Protocol': 'UDP', 'Source_IP': '10.10.10.0/24', 'Dest_IP': '20.20.20.0/24', 'Dest_Port': 443}
    adapted_rules[15] = {'Rule_ID': 16, 'Action': 'DENY', 'Protocol': 'UDP', 'Source_IP': '10.10.10.0/24', 'Dest_IP': '20.20.20.0/24', 'Dest_Port': 443}

    # Overwrite our raw pipeline file so the rest of the framework runs perfectly
    with open(OUTPUT_FILE, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=adapted_rules[0].keys())
        writer.writeheader()
        writer.writerows(adapted_rules)
        
    print(f"Success! Adapted Kaggle data and saved to: {OUTPUT_FILE}")

if __name__ == "__main__":
    adapt_kaggle_data()

