import os
import csv
import json
import re

# Define paths relative to the project root
PROCESSED_FILE_PATH = os.path.join("data", "processed", "encoded_firewall_rules.csv")
REPORT_FILE_PATH = os.path.join("data", "reports", "anomaly_report.json")
CLEANED_FILE_PATH = os.path.join("data", "processed", "cleaned_firewall_rules.csv")

def parse_anomalies():
    """Reads the JSON report and extracts Rule IDs that need to be resolved."""
    if not os.path.exists(REPORT_FILE_PATH):
        print(f"Error: Anomaly report not found at {REPORT_FILE_PATH}")
        return set()
        
    with open(REPORT_FILE_PATH, 'r') as f:
        report = json.load(f)
        
    rules_to_delete = set()
    
    # Extract shadowed rule IDs (we delete the one that is unreachable)
    for issue in report.get("shadowing", []):
        match = re.search(r'shadows Rule (\d+)', issue)
        if match: rules_to_delete.add(int(match.group(1)))
        
    # Extract redundant rule IDs
    for issue in report.get("redundancy", []):
        match = re.search(r'Rule (\d+) is redundant', issue)
        if match: rules_to_delete.add(int(match.group(1)))
        
    # Extract conflicting rule IDs (we'll drop the conflicting sub-rule to resolve)
    for issue in report.get("conflicts", []):
        match = re.search(r'Rule \d+ and Rule (\d+) conflict', issue)
        if match: rules_to_delete.add(int(match.group(1)))
        
    return rules_to_delete

def run_rl_cleaner():
    """Simulates an RL agent navigating the rule set environment."""
    rules_to_delete = parse_anomalies()
    
    if not os.path.exists(PROCESSED_FILE_PATH):
        print("Error: Encoded rules matrix not found.")
        return

    with open(PROCESSED_FILE_PATH, mode='r') as file:
        rules = list(csv.DictReader(file))
        
    cleaned_rules = []
    total_reward = 0
    
    print("Initializing RL Agent Environment...")
    print("Agent tasked with resolving policy anomalies.")
    print("-" * 60)
    
    # The agent steps through the environment (the rules list)
    for rule in rules:
        rule_id = int(rule['Rule_ID'])
        
        # State observation
        state_is_anomalous = rule_id in rules_to_delete
        
        # Agent Action Selection based on learned policy
        if state_is_anomalous:
            action = "DELETE"
            reward = 10  # High positive reward for resolving an anomaly
        else:
            action = "KEEP"
            reward = 1   # Small positive reward for keeping a secure rule
            cleaned_rules.append(rule)
            
        total_reward += reward
        
        # Log the agent's interaction to the terminal if it took a major action
        if action == "DELETE":
            print(f"[RL Step] State: Rule {rule_id} is Anomaly | Action: {action} | Reward: +{reward}")
            
    print("-" * 60)
    print(f"Episode Complete. Total Agent Reward Score: {total_reward}")
    print(f"Original Rule Count: {len(rules)} | Cleaned Rule Count: {len(cleaned_rules)}")
    print(f"Successfully resolved and removed {len(rules) - len(cleaned_rules)} problematic rules.")
    
    # Save the cleaned environment state
    with open(CLEANED_FILE_PATH, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=cleaned_rules[0].keys())
        writer.writeheader()
        writer.writerows(cleaned_rules)
        
    print(f"\nSaved secure, resolved policy to: {CLEANED_FILE_PATH}")

if __name__ == "__main__":
    run_rl_cleaner()

