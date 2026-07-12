import sys
import os

# Ensure the root directory is in the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.data_engineer.kaggle_adapter import adapt_kaggle_data as generate_logs
from src.data_engineer.parse_rules import parse_and_encode
from src.data_engineer.anomaly_detector import detect_anomalies
from src.ga_optimizer.ga_engine import run_genetic_algorithm
from src.rl_agent.rl_cleaner import run_rl_cleaner

def run_pipeline():
    print("-" * 60)
    print("Starting: Firewall-Anomaly-ML-Framework")
    print("-" * 60)
    
    # Stage 1: Data Generation    
    print("[Step 1/5] Executing data generation...")
    # If the Kaggle file doesn't exist, stop execution immediately
    if not os.path.exists("data/raw/log2.csv"):
        print("Source Error: Kaggle dataset not found at data/raw/log2.csv. Pipeline halted.")
        sys.exit(1) 

    # Run your adapter safely knowing the file is there
    generate_logs()
   
    # Stage 2: Data Parsing & Matrix Encoding-
    print("[Step 2/5] Executing rule parsing & Matrix Conversion...")
    if not os.path.exists("data/raw/raw_simulated_firewall_logs.csv"):
        print("Source Error: Raw logs missing. Pipeline halted.")
        sys.exit(1)

    parse_and_encode()
    
    # Stage 3: Anomaly Detection
    print("\n[Step 3/5] Scanning matrix for structural anomalies...")
    detect_anomalies()
    
    # Stage 4: Genetic Algorithm Optimization
    print("\n[Step 4/5] Running GA policy Re-ordering engine...")
    run_genetic_algorithm(generations=50, population_size=15)
    
    # Stage 5: Reinforcement Learning Resolution
    print("\n[Step 5/5] Deploying RL agent for policy De-bloating...")
    run_rl_cleaner()
    
    print("\n" + "-" * 60)
    print("Succes: Full Pipeline Executed Successfully!")
    print("All cleaned and optimized outputs are ready in data/processed/ path")
    print("-" * 60)

if __name__ == "__main__":
    run_pipeline()

