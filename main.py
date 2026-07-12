import sys
import os

# Ensure the root directory is in the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.data_engineer.generate_logs import main as generate_logs
from src.data_engineer.parse_rules import parse_and_encode
from src.data_engineer.anomaly_detector import detect_anomalies
from src.ga_optimizer.ga_engine import run_genetic_algorithm
from src.rl_agent.rl_cleaner import run_rl_cleaner

def run_pipeline():
    print("=" * 60)
    print("STARTING: FIREWALL ANOMALY RESOLUTION ML FRAMEWORK")
    print("=" * 60)
    
    # Stage 1: Data Generation
    print("\n[STAGE 1/5] Executing Data Generation...")
    generate_logs()
    
    # Stage 2: Data Parsing & Matrix Encoding
    print("\n[STAGE 2/5] Executing Rule Parsing & Matrix Conversion...")
    parse_and_encode()
    
    # Stage 3: Anomaly Detection
    print("\n[STAGE 3/5] Scanning Matrix for Structural Anomalies...")
    detect_anomalies()
    
    # Stage 4: Genetic Algorithm Optimization
    print("\n[STAGE 4/5] Running GA Policy Re-Ordering Engine...")
    run_genetic_algorithm(generations=50, population_size=15)
    
    # Stage 5: Reinforcement Learning Resolution
    print("\n[STAGE 5/5] Deploying RL Agent for Policy De-bloating...")
    run_rl_cleaner()
    
    print("\n" + "=" * 60)
    print("SUCCESS: Full Pipeline Executed Successfully!")
    print("All cleaned and optimized outputs are ready in data/processed/")
    print("=" * 60)

if __name__ == "__main__":
    run_pipeline()

