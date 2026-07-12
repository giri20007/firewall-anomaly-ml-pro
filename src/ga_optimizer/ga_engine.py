import os
import csv
import random

PROCESSED_FILE_PATH = os.path.join("data", "processed", "encoded_firewall_rules.csv")
OPTIMIZED_DIR = os.path.join("data", "processed")
OPTIMIZED_FILE_PATH = os.path.join(OPTIMIZED_DIR, "optimized_firewall_rules.csv")

def load_rules():
    """Loads the encoded rules from the processed CSV file."""
    if not os.path.exists(PROCESSED_FILE_PATH):
        print(f"Error: Processed file not found at {PROCESSED_FILE_PATH}")
        return []
    
    rules = []
    with open(PROCESSED_FILE_PATH, mode='r') as file:
        reader = csv.DictReader(file)
        for row in reader:
            rules.append({k: int(v) for k, v in row.items()})
    return rules

def calculate_fitness(chromosome, traffic_weights):
    """
    Fitness Function: Calculates the total evaluation overhead.
    Lower overhead = Higher efficiency (better fitness).
    Overhead is determined by: Position in list * Traffic Weight.
    """
    total_overhead = 0
    for position, rule in enumerate(chromosome):
        rule_id = rule['Rule_ID']
        # If a rule handles heavy traffic, it should be at position 0 (low overhead)
        weight = traffic_weights.get(rule_id, 1)
        total_overhead += position * weight
    return total_overhead

def mutate(chromosome):
    """Mutates a chromosome by swapping the positions of two random rules."""
    idx_a, idx_b = random.sample(range(len(chromosome)), 2)
    chromosome[idx_a], chromosome[idx_b] = chromosome[idx_b], chromosome[idx_a]
    return chromosome

def crossover(parent1, parent2):
    """Performs ordered crossover to mix rule orders without duplicating any rules."""
    size = len(parent1)
    start, end = sorted(random.sample(range(size), 2))
    
    child = [None] * size
    child[start:end] = parent1[start:end]
    
    pointer = 0
    for item in parent2:
        if item not in child:
            while child[pointer] is not None:
                pointer += 1
            child[pointer] = item
            
    return child

def run_genetic_algorithm(generations=100, population_size=20):
    """Main GA engine loop to evolve the most efficient rule order."""
    base_rules = load_rules()
    if not base_rules:
        return

    # Simulate network traffic weight for each rule (Rule 45 and 50 get massive traffic hits)
    # This gives the GA a target to optimize for
    traffic_weights = {i: 1 for i in range(1, len(base_rules) + 1)}
    traffic_weights[45] = 500  
    traffic_weights[50] = 400  

    # Initialize Population (random order permutations)
    population = [random.sample(base_rules, len(base_rules)) for _ in range(population_size)]

    print("Starting Genetic Algorithm rule order optimization...")
    
    for gen in range(generations):
        # Sort population by fitness score (lower overhead is better)
        population = sorted(population, key=lambda chrom: calculate_fitness(chrom, traffic_weights))
        
        # Keep the elite top 2 configurations
        next_generation = population[:2]
        
        # Breed the rest of the new generation
        while len(next_generation) < population_size:
            parent1 = random.choice(population[:10])
            parent2 = random.choice(population[:10])
            
            child = crossover(parent1, parent2)
            
            if random.random() < 0.2:  # 20% Mutation Rate
                child = mutate(child)
                
            next_generation.append(child)
            
        population = next_generation
        
        # Print progress every 20 generations
        if gen % 20 == 0:
            best_fitness = calculate_fitness(population[0], traffic_weights)
            print(f"Generation {gen}: Best Configuration Overhead Score = {best_fitness}")

    # Best individual layout found
    best_layout = population[0]
    
    # Save optimized order to files
    with open(OPTIMIZED_FILE_PATH, mode='w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=best_layout[0].keys())
        writer.writeheader()
        writer.writerows(best_layout)

    print("\nOptimization Complete!")
    print(f"Saved optimized policy configuration order to: {OPTIMIZED_FILE_PATH}")
    print("Top 3 prioritized rules in the new policy:")
    for i in range(3):
        print(f" - Rule Position {i+1}: Original Rule_ID {best_layout[i]['Rule_ID']}")

if __name__ == "__main__":
    run_genetic_algorithm()

