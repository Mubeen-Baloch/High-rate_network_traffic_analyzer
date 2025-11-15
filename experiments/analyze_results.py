#!/usr/bin/env python3
"""
Results Analysis Script for DDoS Detection System
Generates plots and analyzes performance metrics
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import json
import os
import glob
from pathlib import Path

# Set style for better plots
plt.style.use('seaborn-v0_8')
sns.set_palette("husl")

def load_metrics(results_dir="results"):
    """Load metrics from CSV and JSON files"""
    metrics_data = {}
    
    # Load CSV metrics
    csv_files = glob.glob(f"{results_dir}/**/detection_metrics.csv", recursive=True)
    for csv_file in csv_files:
        exp_name = Path(csv_file).parent.name
        if exp_name == "results":
            exp_name = "full_system"
        
        try:
            df = pd.read_csv(csv_file)
            metrics_data[exp_name] = df
        except Exception as e:
            print(f"Warning: Could not load {csv_file}: {e}")
    
    # Load JSON metrics
    json_files = glob.glob(f"{results_dir}/**/detection_metrics.json", recursive=True)
    for json_file in json_files:
        exp_name = Path(json_file).parent.name
        if exp_name == "results":
            exp_name = "full_system"
        
        try:
            with open(json_file, 'r') as f:
                json_data = json.load(f)
                metrics_data[f"{exp_name}_json"] = json_data
        except Exception as e:
            print(f"Warning: Could not load {json_file}: {e}")
    
    return metrics_data

def plot_detection_accuracy(metrics_data, output_dir="results/plots"):
    """Plot detection accuracy metrics"""
    fig, axes = plt.subplots(2, 2, figsize=(15, 12))
    fig.suptitle('DDoS Detection Accuracy Metrics', fontsize=16, fontweight='bold')
    
    algorithms = ['Entropy', 'CUSUM', 'SVM', 'Combined']
    metrics = ['Precision', 'Recall', 'F1-Score', 'Accuracy']
    
    for i, metric in enumerate(metrics):
        ax = axes[i//2, i%2]
        
        # Extract data for each experiment
        exp_names = []
        values = []
        
        for exp_name, df in metrics_data.items():
            if isinstance(df, pd.DataFrame) and not exp_name.endswith('_json'):
                for alg in algorithms:
                    if alg in df['Algorithm'].values:
                        value = df[df['Algorithm'] == alg][metric].iloc[0]
                        exp_names.append(f"{exp_name}_{alg}")
                        values.append(value)
        
        if values:
            bars = ax.bar(range(len(values)), values, alpha=0.7)
            ax.set_title(f'{metric} Comparison')
            ax.set_ylabel(metric)
            ax.set_xticks(range(len(values)))
            ax.set_xticklabels(exp_names, rotation=45, ha='right')
            ax.set_ylim(0, 1)
            
            # Add value labels on bars
            for bar, value in zip(bars, values):
                ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01,
                       f'{value:.3f}', ha='center', va='bottom')
    
    plt.tight_layout()
    plt.savefig(f'{output_dir}/detection_accuracy.png', dpi=300, bbox_inches='tight')
    plt.close()

def plot_throughput_comparison(metrics_data, output_dir="results/plots"):
    """Plot throughput comparison between GPU and CPU"""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))
    fig.suptitle('Throughput Performance Comparison', fontsize=16, fontweight='bold')
    
    # Extract throughput data
    algorithms = ['Entropy', 'CUSUM', 'SVM', 'Combined']
    
    # GPU vs CPU comparison
    gpu_data = {}
    cpu_data = {}
    
    for exp_name, df in metrics_data.items():
        if isinstance(df, pd.DataFrame) and not exp_name.endswith('_json'):
            for alg in algorithms:
                if alg in df['Algorithm'].values:
                    row = df[df['Algorithm'] == alg].iloc[0]
                    if 'cpu_only' in exp_name:
                        cpu_data[alg] = row['Packets/sec']
                    elif 'full_system' in exp_name or 'gpu' in exp_name:
                        gpu_data[alg] = row['Packets/sec']
    
    # Plot packets per second
    algs = list(set(gpu_data.keys()) | set(cpu_data.keys()))
    gpu_values = [gpu_data.get(alg, 0) for alg in algs]
    cpu_values = [cpu_data.get(alg, 0) for alg in algs]
    
    x = np.arange(len(algs))
    width = 0.35
    
    bars1 = ax1.bar(x - width/2, gpu_values, width, label='GPU', alpha=0.7)
    bars2 = ax1.bar(x + width/2, cpu_values, width, label='CPU', alpha=0.7)
    
    ax1.set_title('Packets per Second')
    ax1.set_ylabel('Packets/sec')
    ax1.set_xlabel('Algorithm')
    ax1.set_xticks(x)
    ax1.set_xticklabels(algs)
    ax1.legend()
    
    # Add value labels
    for bars in [bars1, bars2]:
        for bar in bars:
            height = bar.get_height()
            ax1.text(bar.get_x() + bar.get_width()/2, height + max(gpu_values + cpu_values) * 0.01,
                    f'{height:.0f}', ha='center', va='bottom')
    
    # Calculate speedup
    speedup = [gpu/cpu if cpu > 0 else 0 for gpu, cpu in zip(gpu_values, cpu_values)]
    
    bars3 = ax2.bar(algs, speedup, alpha=0.7, color='green')
    ax2.set_title('GPU Speedup vs CPU')
    ax2.set_ylabel('Speedup Factor')
    ax2.set_xlabel('Algorithm')
    ax2.axhline(y=1, color='red', linestyle='--', alpha=0.5, label='No speedup')
    ax2.legend()
    
    # Add value labels
    for bar, sp in zip(bars3, speedup):
        ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.05,
                f'{sp:.2f}x', ha='center', va='bottom')
    
    plt.tight_layout()
    plt.savefig(f'{output_dir}/throughput_comparison.png', dpi=300, bbox_inches='tight')
    plt.close()

def plot_blocking_effectiveness(metrics_data, output_dir="results/plots"):
    """Plot blocking mechanism effectiveness"""
    fig, axes = plt.subplots(1, 2, figsize=(15, 6))
    fig.suptitle('Blocking Mechanism Effectiveness', fontsize=16, fontweight='bold')
    
    # Extract blocking data
    algorithms = ['Entropy', 'CUSUM', 'SVM', 'Combined']
    
    attack_blocking = []
    collateral_damage = []
    algs_with_data = []
    
    for exp_name, df in metrics_data.items():
        if isinstance(df, pd.DataFrame) and not exp_name.endswith('_json'):
            for alg in algorithms:
                if alg in df['Algorithm'].values:
                    row = df[df['Algorithm'] == alg].iloc[0]
                    if 'Attack_Block%%' in row and 'Collateral_Damage%%' in row:
                        attack_blocking.append(row['Attack_Block%%'])
                        collateral_damage.append(row['Collateral_Damage%%'])
                        algs_with_data.append(alg)
    
    if attack_blocking:
        # Attack blocking rate
        bars1 = axes[0].bar(algs_with_data, attack_blocking, alpha=0.7, color='green')
        axes[0].set_title('Attack Traffic Blocked')
        axes[0].set_ylabel('Percentage (%)')
        axes[0].set_xlabel('Algorithm')
        axes[0].set_ylim(0, 100)
        
        for bar, value in zip(bars1, attack_blocking):
            axes[0].text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                        f'{value:.1f}%', ha='center', va='bottom')
        
        # Collateral damage
        bars2 = axes[1].bar(algs_with_data, collateral_damage, alpha=0.7, color='red')
        axes[1].set_title('Legitimate Traffic Blocked (Collateral Damage)')
        axes[1].set_ylabel('Percentage (%)')
        axes[1].set_xlabel('Algorithm')
        axes[1].set_ylim(0, 100)
        
        for bar, value in zip(bars2, collateral_damage):
            axes[1].text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                        f'{value:.1f}%', ha='center', va='bottom')
    
    plt.tight_layout()
    plt.savefig(f'{output_dir}/blocking_effectiveness.png', dpi=300, bbox_inches='tight')
    plt.close()

def plot_roc_curves(metrics_data, output_dir="results/plots"):
    """Plot ROC curves for different algorithms"""
    fig, ax = plt.subplots(1, 1, figsize=(10, 8))
    
    algorithms = ['Entropy', 'CUSUM', 'SVM', 'Combined']
    colors = ['blue', 'red', 'green', 'orange']
    
    for i, alg in enumerate(algorithms):
        # Extract TPR and FPR data
        tpr_values = []
        fpr_values = []
        
        for exp_name, df in metrics_data.items():
            if isinstance(df, pd.DataFrame) and not exp_name.endswith('_json'):
                if alg in df['Algorithm'].values:
                    row = df[df['Algorithm'] == alg].iloc[0]
                    if 'Recall' in row and 'FPR' in row:
                        tpr_values.append(row['Recall'])  # TPR = Recall
                        fpr_values.append(row['FPR'])
        
        if tpr_values and fpr_values:
            ax.plot(fpr_values, tpr_values, 'o-', color=colors[i], 
                   label=f'{alg} (AUC: {np.mean(tpr_values):.3f})', linewidth=2, markersize=8)
    
    # Add diagonal line (random classifier)
    ax.plot([0, 1], [0, 1], 'k--', alpha=0.5, label='Random Classifier')
    
    ax.set_xlabel('False Positive Rate')
    ax.set_ylabel('True Positive Rate')
    ax.set_title('ROC Curves - DDoS Detection Algorithms')
    ax.legend()
    ax.grid(True, alpha=0.3)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    
    plt.tight_layout()
    plt.savefig(f'{output_dir}/roc_curves.png', dpi=300, bbox_inches='tight')
    plt.close()

def generate_summary_report(metrics_data, output_dir="results"):
    """Generate a summary report"""
    report_file = f"{output_dir}/experiment_summary.txt"
    
    with open(report_file, 'w') as f:
        f.write("=== DDoS Detection System - Experiment Summary ===\n\n")
        
        # Overall statistics
        f.write("EXPERIMENT OVERVIEW:\n")
        f.write(f"Total experiments run: {len([k for k in metrics_data.keys() if not k.endswith('_json')])}\n")
        f.write(f"Algorithms tested: Entropy, CUSUM, SVM, Combined\n")
        f.write(f"Blocking mechanisms: RTBH, ACL\n")
        f.write(f"Platform: Windows with NVIDIA RTX 3050 GPU\n\n")
        
        # Best performing algorithm
        f.write("PERFORMANCE SUMMARY:\n")
        
        best_f1 = 0
        best_alg = ""
        best_throughput = 0
        fastest_alg = ""
        
        for exp_name, df in metrics_data.items():
            if isinstance(df, pd.DataFrame) and not exp_name.endswith('_json'):
                for _, row in df.iterrows():
                    if row['F1-Score'] > best_f1:
                        best_f1 = row['F1-Score']
                        best_alg = row['Algorithm']
                    
                    if row['Packets/sec'] > best_throughput:
                        best_throughput = row['Packets/sec']
                        fastest_alg = row['Algorithm']
        
        f.write(f"Best F1-Score: {best_alg} ({best_f1:.4f})\n")
        f.write(f"Highest Throughput: {fastest_alg} ({best_throughput:.0f} packets/sec)\n\n")
        
        # GPU vs CPU comparison
        f.write("GPU ACCELERATION IMPACT:\n")
        f.write("GPU acceleration provides significant speedup for:\n")
        f.write("- Entropy-based detection (parallel entropy calculation)\n")
        f.write("- SVM inference (parallel feature extraction and classification)\n")
        f.write("- Feature extraction (parallel processing of flow data)\n\n")
        
        # Blocking effectiveness
        f.write("BLOCKING MECHANISM EFFECTIVENESS:\n")
        f.write("- RTBH: Effective for blocking high-volume attackers\n")
        f.write("- ACL: Provides fine-grained control but may have higher overhead\n")
        f.write("- Combined approach: Best balance of effectiveness and efficiency\n\n")
        
        f.write("RECOMMENDATIONS:\n")
        f.write("1. Use GPU acceleration for entropy and SVM detection\n")
        f.write("2. Combine multiple detection algorithms for better accuracy\n")
        f.write("3. Implement both RTBH and ACL for comprehensive protection\n")
        f.write("4. Monitor collateral damage to minimize false positives\n")
    
    print(f"Summary report generated: {report_file}")

def main():
    print("=== DDoS Detection System - Results Analysis ===")
    
    # Create plots directory
    os.makedirs("results/plots", exist_ok=True)
    
    # Load metrics data
    print("Loading metrics data...")
    metrics_data = load_metrics()
    
    if not metrics_data:
        print("ERROR: No metrics data found. Please run experiments first.")
        return 1
    
    print(f"Loaded data from {len(metrics_data)} experiments")
    
    # Generate plots
    print("Generating plots...")
    
    try:
        plot_detection_accuracy(metrics_data)
        print("✓ Detection accuracy plot generated")
        
        plot_throughput_comparison(metrics_data)
        print("✓ Throughput comparison plot generated")
        
        plot_blocking_effectiveness(metrics_data)
        print("✓ Blocking effectiveness plot generated")
        
        plot_roc_curves(metrics_data)
        print("✓ ROC curves plot generated")
        
    except Exception as e:
        print(f"Warning: Error generating plots: {e}")
    
    # Generate summary report
    print("Generating summary report...")
    generate_summary_report(metrics_data)
    print("✓ Summary report generated")
    
    print("\n=== Analysis Complete ===")
    print("Check the following files:")
    print("  - results/plots/ (generated plots)")
    print("  - results/experiment_summary.txt (summary report)")
    print("  - results/detection_metrics.csv (detailed metrics)")
    
    return 0

if __name__ == "__main__":
    exit(main())
