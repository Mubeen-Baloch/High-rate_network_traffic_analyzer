#!/usr/bin/env python3
"""
Comprehensive Presentation Generator for DDoS Detection System
Generates enhanced visualizations, interactive dashboard, and presentation materials
"""

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import seaborn as sns
import json
import os
from pathlib import Path
from datetime import datetime

# Set style for professional plots
plt.style.use('seaborn-v0_8-darkgrid')
sns.set_palette("husl")
plt.rcParams['figure.dpi'] = 300
plt.rcParams['savefig.dpi'] = 300
plt.rcParams['font.size'] = 10
plt.rcParams['axes.labelsize'] = 11
plt.rcParams['axes.titlesize'] = 13
plt.rcParams['xtick.labelsize'] = 9
plt.rcParams['ytick.labelsize'] = 9
plt.rcParams['legend.fontsize'] = 9

def load_metrics(results_dir="results"):
    """Load metrics from CSV and JSON files"""
    metrics_data = {}
    
    # Load CSV metrics
    csv_file = f"{results_dir}/detection_metrics.csv"
    if os.path.exists(csv_file):
        try:
            df = pd.read_csv(csv_file)
            metrics_data['csv'] = df
        except Exception as e:
            print(f"Warning: Could not load {csv_file}: {e}")
    
    # Load JSON metrics
    json_file = f"{results_dir}/detection_metrics.json"
    if os.path.exists(json_file):
        try:
            with open(json_file, 'r') as f:
                json_data = json.load(f)
                metrics_data['json'] = json_data
        except Exception as e:
            print(f"Warning: Could not load {json_file}: {e}")
    
    return metrics_data

def plot_comprehensive_detection_metrics(metrics_data, output_dir="presentation/plots"):
    """Create comprehensive detection accuracy visualization"""
    os.makedirs(output_dir, exist_ok=True)
    
    if 'csv' not in metrics_data:
        print("No CSV data available for detection metrics")
        return
    
    df = metrics_data['csv']
    algorithms = ['Entropy', 'CUSUM', 'SVM', 'Combined']
    
    # Filter to only include algorithms we have data for
    available_algs = [alg for alg in algorithms if alg in df['Algorithm'].values]
    if not available_algs:
        print("No algorithm data available")
        return
    
    fig, axes = plt.subplots(2, 3, figsize=(18, 12))
    fig.suptitle('Comprehensive DDoS Detection Performance Analysis', 
                 fontsize=16, fontweight='bold', y=0.995)
    
    metrics_to_plot = [
        ('Precision', 0, 0, 'Precision Score'),
        ('Recall', 0, 1, 'Recall (True Positive Rate)'),
        ('F1-Score', 0, 2, 'F1-Score (Harmonic Mean)'),
        ('Accuracy', 1, 0, 'Overall Accuracy'),
        ('FPR', 1, 1, 'False Positive Rate'),
        ('Attack_Block%', 1, 2, 'Attack Traffic Blocked (%)')
    ]
    
    colors = sns.color_palette("husl", len(available_algs))
    
    for metric, row, col, title in metrics_to_plot:
        ax = axes[row, col]
        values = []
        labels = []
        
        for alg in available_algs:
            alg_data = df[df['Algorithm'] == alg]
            if not alg_data.empty and metric in alg_data.columns:
                value = alg_data[metric].iloc[0]
                values.append(value)
                labels.append(alg)
        
        if values:
            bars = ax.bar(labels, values, color=colors[:len(values)], alpha=0.8, edgecolor='black', linewidth=1.5)
            ax.set_title(title, fontweight='bold', pad=10)
            ax.set_ylabel('Score' if metric != 'Attack_Block%' else 'Percentage (%)')
            ax.grid(True, alpha=0.3, axis='y')
            
            # Add value labels on bars
            for bar, value in zip(bars, values):
                height = bar.get_height()
                ax.text(bar.get_x() + bar.get_width()/2, height + max(values) * 0.02,
                       f'{value:.3f}' if metric != 'Attack_Block%' else f'{value:.1f}%',
                       ha='center', va='bottom', fontweight='bold')
            
            # Set y-axis limits
            if metric in ['Precision', 'Recall', 'F1-Score', 'Accuracy']:
                ax.set_ylim(0, 1.1)
            elif metric == 'FPR':
                ax.set_ylim(0, max(1.0, max(values) * 1.2))
            else:
                ax.set_ylim(0, max(100, max(values) * 1.1))
    
    plt.tight_layout(rect=[0, 0, 1, 0.99])
    plt.savefig(f'{output_dir}/comprehensive_detection_metrics.png', 
                bbox_inches='tight', facecolor='white')
    plt.close()
    print(f"✓ Comprehensive detection metrics plot saved")

def plot_performance_comparison(metrics_data, output_dir="presentation/plots"):
    """Create performance comparison visualization"""
    os.makedirs(output_dir, exist_ok=True)
    
    if 'csv' not in metrics_data:
        return
    
    df = metrics_data['csv']
    algorithms = ['Entropy', 'CUSUM', 'SVM', 'Combined']
    available_algs = [alg for alg in algorithms if alg in df['Algorithm'].values]
    
    if not available_algs:
        return
    
    fig, axes = plt.subplots(2, 2, figsize=(16, 12))
    fig.suptitle('Performance Metrics Comparison', fontsize=16, fontweight='bold')
    
    # Throughput (Packets/sec)
    ax1 = axes[0, 0]
    throughput = []
    labels = []
    for alg in available_algs:
        alg_data = df[df['Algorithm'] == alg]
        if not alg_data.empty and 'Packets/sec' in alg_data.columns:
            value = alg_data['Packets/sec'].iloc[0]
            throughput.append(value / 1e6)  # Convert to millions
            labels.append(alg)
    
    if throughput:
        bars = ax1.bar(labels, throughput, color=sns.color_palette("husl", len(labels)), 
                      alpha=0.8, edgecolor='black', linewidth=1.5)
        ax1.set_title('Processing Throughput', fontweight='bold')
        ax1.set_ylabel('Million Packets/sec')
        ax1.grid(True, alpha=0.3, axis='y')
        for bar, val in zip(bars, throughput):
            ax1.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(throughput) * 0.02,
                    f'{val:.2f}M', ha='center', va='bottom', fontweight='bold')
    
    # Throughput (Gbps)
    ax2 = axes[0, 1]
    gbps = []
    for alg in available_algs:
        alg_data = df[df['Algorithm'] == alg]
        if not alg_data.empty and 'Gbps' in alg_data.columns:
            value = alg_data['Gbps'].iloc[0]
            gbps.append(value)
            labels_gbps = labels.copy()
    
    if gbps:
        bars = ax2.bar(labels_gbps, gbps, color=sns.color_palette("husl", len(labels_gbps)), 
                      alpha=0.8, edgecolor='black', linewidth=1.5)
        ax2.set_title('Network Throughput', fontweight='bold')
        ax2.set_ylabel('Gigabits per Second (Gbps)')
        ax2.grid(True, alpha=0.3, axis='y')
        for bar, val in zip(bars, gbps):
            ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(gbps) * 0.02,
                    f'{val:.2f}', ha='center', va='bottom', fontweight='bold')
    
    # GPU Utilization
    ax3 = axes[1, 0]
    gpu_util = []
    for alg in available_algs:
        alg_data = df[df['Algorithm'] == alg]
        if not alg_data.empty and 'GPU_Util%' in alg_data.columns:
            value = alg_data['GPU_Util%'].iloc[0]
            gpu_util.append(value)
    
    if gpu_util:
        bars = ax3.bar(labels, gpu_util, color=sns.color_palette("husl", len(labels)), 
                      alpha=0.8, edgecolor='black', linewidth=1.5)
        ax3.set_title('GPU Utilization', fontweight='bold')
        ax3.set_ylabel('Utilization (%)')
        ax3.set_ylim(0, 100)
        ax3.grid(True, alpha=0.3, axis='y')
        for bar, val in zip(bars, gpu_util):
            ax3.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 2,
                    f'{val:.1f}%', ha='center', va='bottom', fontweight='bold')
    
    # Blocking Effectiveness
    ax4 = axes[1, 1]
    attack_block = []
    collateral = []
    for alg in available_algs:
        alg_data = df[df['Algorithm'] == alg]
        if not alg_data.empty:
            if 'Attack_Block%' in alg_data.columns:
                attack_block.append(alg_data['Attack_Block%'].iloc[0])
            else:
                attack_block.append(0)
            if 'Collateral_Damage%' in alg_data.columns:
                collateral.append(alg_data['Collateral_Damage%'].iloc[0])
            else:
                collateral.append(0)
    
    if attack_block:
        x = np.arange(len(labels))
        width = 0.35
        bars1 = ax4.bar(x - width/2, attack_block, width, label='Attack Blocked', 
                       color='green', alpha=0.8, edgecolor='black', linewidth=1.5)
        bars2 = ax4.bar(x + width/2, collateral, width, label='Collateral Damage', 
                       color='red', alpha=0.8, edgecolor='black', linewidth=1.5)
        ax4.set_title('Blocking Effectiveness', fontweight='bold')
        ax4.set_ylabel('Percentage (%)')
        ax4.set_xticks(x)
        ax4.set_xticklabels(labels)
        ax4.legend()
        ax4.set_ylim(0, max(100, max(attack_block + collateral) * 1.1))
        ax4.grid(True, alpha=0.3, axis='y')
        
        for bars in [bars1, bars2]:
            for bar in bars:
                height = bar.get_height()
                ax4.text(bar.get_x() + bar.get_width()/2, height + 1,
                        f'{height:.1f}%', ha='center', va='bottom', fontsize=8)
    
    plt.tight_layout()
    plt.savefig(f'{output_dir}/performance_comparison.png', 
                bbox_inches='tight', facecolor='white')
    plt.close()
    print(f"✓ Performance comparison plot saved")

def plot_algorithm_radar_chart(metrics_data, output_dir="presentation/plots"):
    """Create radar chart comparing algorithms"""
    os.makedirs(output_dir, exist_ok=True)
    
    if 'csv' not in metrics_data:
        return
    
    df = metrics_data['csv']
    algorithms = ['Entropy', 'CUSUM', 'SVM']
    available_algs = [alg for alg in algorithms if alg in df['Algorithm'].values]
    
    if not available_algs:
        return
    
    # Normalize metrics to 0-1 scale for radar chart
    categories = ['Precision', 'Recall', 'F1-Score', 'Accuracy', 'Throughput', 'GPU Util']
    
    fig, ax = plt.subplots(figsize=(12, 10), subplot_kw=dict(projection='polar'))
    
    angles = np.linspace(0, 2 * np.pi, len(categories), endpoint=False).tolist()
    angles += angles[:1]  # Complete the circle
    
    colors = sns.color_palette("husl", len(available_algs))
    
    for idx, alg in enumerate(available_algs):
        alg_data = df[df['Algorithm'] == alg].iloc[0]
        values = []
        
        # Normalize each metric
        values.append(alg_data.get('Precision', 0))
        values.append(alg_data.get('Recall', 0))
        values.append(alg_data.get('F1-Score', 0))
        values.append(alg_data.get('Accuracy', 0))
        
        # Normalize throughput (assuming max 50M packets/sec)
        throughput = alg_data.get('Packets/sec', 0) / 1e6
        values.append(min(throughput / 50.0, 1.0))
        
        # Normalize GPU util (0-100%)
        gpu_util = alg_data.get('GPU_Util%', 0) / 100.0
        values.append(gpu_util)
        
        values += values[:1]  # Complete the circle
        
        ax.plot(angles, values, 'o-', linewidth=2, label=alg, color=colors[idx])
        ax.fill(angles, values, alpha=0.25, color=colors[idx])
    
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(categories)
    ax.set_ylim(0, 1)
    ax.set_title('Algorithm Performance Comparison (Normalized)', 
                fontsize=14, fontweight='bold', pad=20)
    ax.legend(loc='upper right', bbox_to_anchor=(1.3, 1.1))
    ax.grid(True)
    
    plt.tight_layout()
    plt.savefig(f'{output_dir}/algorithm_radar_chart.png', 
                bbox_inches='tight', facecolor='white')
    plt.close()
    print(f"✓ Radar chart saved")

def plot_roc_comparison(metrics_data, output_dir="presentation/plots"):
    """Create enhanced ROC curve comparison"""
    os.makedirs(output_dir, exist_ok=True)
    
    if 'csv' not in metrics_data:
        return
    
    df = metrics_data['csv']
    algorithms = ['Entropy', 'CUSUM', 'SVM', 'Combined']
    available_algs = [alg for alg in algorithms if alg in df['Algorithm'].values]
    
    if not available_algs:
        return
    
    fig, ax = plt.subplots(figsize=(10, 8))
    
    colors = sns.color_palette("husl", len(available_algs))
    
    for idx, alg in enumerate(available_algs):
        alg_data = df[df['Algorithm'] == alg].iloc[0]
        recall = alg_data.get('Recall', 0)
        fpr = alg_data.get('FPR', 0)
        
        ax.scatter(fpr, recall, s=200, color=colors[idx], 
                  label=f'{alg} (TPR={recall:.3f}, FPR={fpr:.3f})', 
                  edgecolors='black', linewidth=2, zorder=5)
    
    # Add diagonal line (random classifier)
    ax.plot([0, 1], [0, 1], 'k--', alpha=0.5, linewidth=2, label='Random Classifier')
    
    ax.set_xlabel('False Positive Rate (FPR)', fontsize=12, fontweight='bold')
    ax.set_ylabel('True Positive Rate (TPR / Recall)', fontsize=12, fontweight='bold')
    ax.set_title('ROC Space Comparison - DDoS Detection Algorithms', 
                fontsize=14, fontweight='bold', pad=15)
    ax.legend(loc='lower right', fontsize=10, framealpha=0.9)
    ax.grid(True, alpha=0.3, linestyle='--')
    ax.set_xlim(-0.05, 1.05)
    ax.set_ylim(-0.05, 1.05)
    
    # Add quadrant labels
    ax.text(0.5, 0.95, 'Best Performance', ha='center', va='top', 
           fontsize=11, fontweight='bold', color='green',
           bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
    
    plt.tight_layout()
    plt.savefig(f'{output_dir}/roc_comparison.png', 
                bbox_inches='tight', facecolor='white')
    plt.close()
    print(f"✓ ROC comparison plot saved")

def generate_html_dashboard(metrics_data, output_dir="presentation"):
    """Generate interactive HTML dashboard"""
    os.makedirs(output_dir, exist_ok=True)
    
    if 'csv' not in metrics_data:
        print("No CSV data available for dashboard")
        return
    
    df = metrics_data['csv']
    json_data = metrics_data.get('json', {})
    
    # Get algorithm data
    algorithms = ['Entropy', 'CUSUM', 'SVM', 'Combined']
    available_algs = [alg for alg in algorithms if alg in df['Algorithm'].values]
    
    # Prepare data for dashboard
    alg_data_dict = {}
    for alg in available_algs:
        alg_row = df[df['Algorithm'] == alg].iloc[0]
        alg_data_dict[alg] = {
            'precision': alg_row.get('Precision', 0),
            'recall': alg_row.get('Recall', 0),
            'f1_score': alg_row.get('F1-Score', 0),
            'accuracy': alg_row.get('Accuracy', 0),
            'fpr': alg_row.get('FPR', 0),
            'throughput_pps': alg_row.get('Packets/sec', 0),
            'throughput_gbps': alg_row.get('Gbps', 0),
            'gpu_util': alg_row.get('GPU_Util%', 0),
            'attack_block': alg_row.get('Attack_Block%', 0),
            'collateral': alg_row.get('Collateral_Damage%', 0)
        }
    
    # Get dataset info
    dataset_row = df[df['Algorithm'] == 'Dataset']
    dataset_info = {}
    if not dataset_row.empty:
        dataset_info = {
            'throughput_pps': dataset_row['Packets/sec'].iloc[0],
            'throughput_gbps': dataset_row['Gbps'].iloc[0]
        }
    
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DDoS Detection System - Performance Dashboard</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
            padding: 20px;
            min-height: 100vh;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
        }}
        
        .header p {{
            font-size: 1.2em;
            opacity: 0.9;
        }}
        
        .content {{
            padding: 40px;
        }}
        
        .section {{
            margin-bottom: 40px;
        }}
        
        .section-title {{
            font-size: 1.8em;
            color: #667eea;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid #667eea;
        }}
        
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .metric-card {{
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            border-radius: 10px;
            padding: 25px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
            transition: transform 0.3s ease;
        }}
        
        .metric-card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 10px 25px rgba(0,0,0,0.2);
        }}
        
        .metric-card h3 {{
            color: #667eea;
            margin-bottom: 15px;
            font-size: 1.3em;
        }}
        
        .algorithm-section {{
            background: #f8f9fa;
            border-radius: 10px;
            padding: 25px;
            margin-bottom: 20px;
            border-left: 5px solid #667eea;
        }}
        
        .algorithm-section h3 {{
            color: #667eea;
            font-size: 1.5em;
            margin-bottom: 20px;
        }}
        
        .metric-row {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 15px;
        }}
        
        .metric-item {{
            background: white;
            padding: 15px;
            border-radius: 8px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }}
        
        .metric-label {{
            font-weight: bold;
            color: #666;
            font-size: 0.9em;
            margin-bottom: 5px;
        }}
        
        .metric-value {{
            font-size: 1.5em;
            color: #667eea;
            font-weight: bold;
        }}
        
        .plot-container {{
            text-align: center;
            margin: 30px 0;
        }}
        
        .plot-container img {{
            max-width: 100%;
            border-radius: 10px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
        }}
        
        .footer {{
            background: #2c3e50;
            color: white;
            padding: 20px;
            text-align: center;
        }}
        
        .badge {{
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: bold;
            margin: 5px;
        }}
        
        .badge-success {{
            background: #28a745;
            color: white;
        }}
        
        .badge-warning {{
            background: #ffc107;
            color: #333;
        }}
        
        .badge-danger {{
            background: #dc3545;
            color: white;
        }}
        
        .badge-info {{
            background: #17a2b8;
            color: white;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚀 DDoS Detection System</h1>
            <p>High-Rate Network Traffic Analyzer - Performance Dashboard</p>
            <p style="margin-top: 10px; font-size: 0.9em;">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="content">
            <div class="section">
                <h2 class="section-title">📊 System Overview</h2>
                <div class="metrics-grid">
                    <div class="metric-card">
                        <h3>Dataset Traffic Rate</h3>
                        <div class="metric-value">{dataset_info.get('throughput_pps', 0):,.0f}</div>
                        <div class="metric-label">Packets per Second</div>
                        <div class="metric-value" style="font-size: 1.2em; margin-top: 10px;">{dataset_info.get('throughput_gbps', 0):.4f} Gbps</div>
                    </div>
                    <div class="metric-card">
                        <h3>Algorithms Tested</h3>
                        <div class="metric-value">{len(available_algs)}</div>
                        <div class="metric-label">Detection Methods</div>
                    </div>
                    <div class="metric-card">
                        <h3>Platform</h3>
                        <div class="metric-value">GPU-Accelerated</div>
                        <div class="metric-label">NVIDIA RTX 3050</div>
                    </div>
                </div>
            </div>
"""
    
    # Add algorithm sections
    for alg in available_algs:
        data = alg_data_dict[alg]
        html_content += f"""
            <div class="algorithm-section">
                <h3>🔍 {alg} Detection Algorithm</h3>
                <div class="metric-row">
                    <div class="metric-item">
                        <div class="metric-label">Precision</div>
                        <div class="metric-value">{data['precision']:.4f}</div>
                    </div>
                    <div class="metric-item">
                        <div class="metric-label">Recall</div>
                        <div class="metric-value">{data['recall']:.4f}</div>
                    </div>
                    <div class="metric-item">
                        <div class="metric-label">F1-Score</div>
                        <div class="metric-value">{data['f1_score']:.4f}</div>
                    </div>
                    <div class="metric-item">
                        <div class="metric-label">Accuracy</div>
                        <div class="metric-value">{data['accuracy']:.4f}</div>
                    </div>
                </div>
                <div class="metric-row">
                    <div class="metric-item">
                        <div class="metric-label">False Positive Rate</div>
                        <div class="metric-value">{data['fpr']:.4f}</div>
                    </div>
                    <div class="metric-item">
                        <div class="metric-label">Throughput</div>
                        <div class="metric-value">{data['throughput_pps']/1e6:.2f}M pps</div>
                    </div>
                    <div class="metric-item">
                        <div class="metric-label">Network Throughput</div>
                        <div class="metric-value">{data['throughput_gbps']:.2f} Gbps</div>
                    </div>
                    <div class="metric-item">
                        <div class="metric-label">GPU Utilization</div>
                        <div class="metric-value">{data['gpu_util']:.1f}%</div>
                    </div>
                </div>
                <div class="metric-row">
                    <div class="metric-item">
                        <div class="metric-label">Attack Traffic Blocked</div>
                        <div class="metric-value">{data['attack_block']:.1f}%</div>
                    </div>
                    <div class="metric-item">
                        <div class="metric-label">Collateral Damage</div>
                        <div class="metric-value">{data['collateral']:.1f}%</div>
                    </div>
                </div>
            </div>
"""
    
    # Add plot references
    html_content += """
            <div class="section">
                <h2 class="section-title">📈 Visualizations</h2>
                <div class="plot-container">
                    <h3>Comprehensive Detection Metrics</h3>
                    <img src="plots/comprehensive_detection_metrics.png" alt="Detection Metrics">
                </div>
                <div class="plot
                                <div class="plot-container">
                    <h3>Comprehensive Detection Metrics</h3>
                    <img src="plots/comprehensive_detection_metrics.png" alt="Detection Metrics">
                </div>
                <div class="plot-container">
                    <h3>Performance Comparison</h3>
                    <img src="plots/performance_comparison.png" alt="Performance Comparison">
                </div>
                <div class="plot-container">
                    <h3>ROC Space Comparison</h3>
                    <img src="plots/roc_comparison.png" alt="ROC Comparison">
                </div>
                <div class="plot-container">
                    <h3>Algorithm Radar Chart</h3>
                    <img src="plots/algorithm_radar_chart.png" alt="Radar Chart">
                </div>
            </div>
        </div>
        
        <div class="footer">
            <p>High-Rate Network Traffic Analyzer for Early DDoS Detection and Mitigation</p>
            <p>Parallel and Distributed Computing Project | GPU-Accelerated OpenCL Implementation</p>
        </div>
    </div>
</body>
</html>
"""
    
    # Write HTML file
    html_file = f"{output_dir}/dashboard.html"
    with open(html_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print(f"✓ HTML dashboard saved to {html_file}")

def generate_presentation_slides(metrics_data, output_dir="presentation"):
    """Generate presentation slides in HTML format"""
    os.makedirs(output_dir, exist_ok=True)
    
    if 'csv' not in metrics_data:
        print("No CSV data available for slides")
        return
    
    df = metrics_data['csv']
    algorithms = ['Entropy', 'CUSUM', 'SVM', 'Combined']
    available_algs = [alg for alg in algorithms if alg in df['Algorithm'].values]
    
    # Prepare algorithm data
    alg_data_dict = {}
    for alg in available_algs:
        alg_row = df[df['Algorithm'] == alg].iloc[0]
        alg_data_dict[alg] = {
            'precision': alg_row.get('Precision', 0),
            'recall': alg_row.get('Recall', 0),
            'f1_score': alg_row.get('F1-Score', 0),
            'accuracy': alg_row.get('Accuracy', 0),
            'fpr': alg_row.get('FPR', 0),
            'throughput_pps': alg_row.get('Packets/sec', 0),
            'throughput_gbps': alg_row.get('Gbps', 0),
            'gpu_util': alg_row.get('GPU_Util%', 0),
            'attack_block': alg_row.get('Attack_Block%', 0),
            'collateral': alg_row.get('Collateral_Damage%', 0)
        }
    
    slides_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DDoS Detection System - Presentation</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }}
        .slide {{ 
            width: 100vw; 
            height: 100vh; 
            display: none; 
            padding: 60px; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            overflow-y: auto;
        }}
        .slide.active {{ display: block; }}
        .slide h1 {{ font-size: 3em; margin-bottom: 30px; text-shadow: 2px 2px 4px rgba(0,0,0,0.3); }}
        .slide h2 {{ font-size: 2.5em; margin-bottom: 20px; color: #ffd700; }}
        .slide h3 {{ font-size: 1.8em; margin-bottom: 15px; }}
        .slide-content {{ background: rgba(255,255,255,0.95); color: #333; padding: 40px; border-radius: 15px; margin-top: 20px; }}
        .nav {{ position: fixed; bottom: 20px; right: 20px; z-index: 1000; }}
        .nav button {{ padding: 15px 30px; margin: 5px; font-size: 16px; cursor: pointer; border: none; border-radius: 5px; background: white; color: #667eea; }}
        .metric-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 20px 0; }}
        .metric-box {{ background: #f0f0f0; padding: 20px; border-radius: 10px; text-align: center; }}
        .metric-value {{ font-size: 2em; font-weight: bold; color: #667eea; }}
        .metric-label {{ color: #666; margin-top: 10px; }}
    </style>
</head>
<body>
    <!-- Slide 1: Title -->
    <div class="slide active">
        <h1>🚀 High-Rate Network Traffic Analyzer</h1>
        <h2>Early DDoS Detection and Mitigation</h2>
        <div class="slide-content">
            <h3>GPU-Accelerated OpenCL Implementation</h3>
            <p style="font-size: 1.3em; margin-top: 20px;">Parallel and Distributed Computing Project</p>
            <p style="font-size: 1.1em; margin-top: 10px;">Generated: {datetime.now().strftime('%Y-%m-%d')}</p>
        </div>
    </div>
    
    <!-- Slide 2: Overview -->
    <div class="slide">
        <h2>📋 Project Overview</h2>
        <div class="slide-content">
            <h3>Objectives</h3>
            <ul style="font-size: 1.3em; line-height: 2;">
                <li>Develop high-performance DDoS detection using GPU acceleration</li>
                <li>Implement three detection algorithms (Entropy, CUSUM, SVM)</li>
                <li>Evaluate blocking mechanisms (RTBH, ACL)</li>
                <li>Analyze performance across multiple metrics</li>
            </ul>
            <h3 style="margin-top: 30px;">Key Technologies</h3>
            <p style="font-size: 1.2em;">OpenCL 3.0 | NVIDIA RTX 3050 | CIC-DDoS2019 Dataset</p>
        </div>
    </div>
    
    <!-- Slide 3: System Architecture -->
    <div class="slide">
        <h2>🏗️ System Architecture</h2>
        <div class="slide-content">
            <div style="text-align: center; font-size: 1.2em; line-height: 2.5;">
                <p><strong>Data Input</strong> → <strong>Detection Layer</strong> → <strong>Blocking Layer</strong></p>
                <p style="margin-top: 30px;">↓</p>
                <p><strong>GPU Kernels (OpenCL)</strong></p>
                <p style="margin-top: 30px;">↓</p>
                <p><strong>Metrics & Analysis</strong></p>
            </div>
            <h3 style="margin-top: 40px;">Detection Algorithms</h3>
            <ul style="font-size: 1.2em; line-height: 2;">
                <li><strong>Entropy-Based:</strong> GPU-accelerated Shannon entropy calculation</li>
                <li><strong>CUSUM Statistical:</strong> CPU-based cumulative sum monitoring</li>
                <li><strong>SVM Machine Learning:</strong> GPU-accelerated feature extraction & classification</li>
            </ul>
        </div>
    </div>
"""
    
    # Add algorithm performance slides
    for alg in available_algs:
        data = alg_data_dict[alg]
        slides_html += f"""
    <!-- Slide: {alg} Performance -->
    <div class="slide">
        <h2>🔍 {alg} Detection Algorithm</h2>
        <div class="slide-content">
            <div class="metric-grid">
                <div class="metric-box">
                    <div class="metric-value">{data['precision']:.4f}</div>
                    <div class="metric-label">Precision</div>
                </div>
                <div class="metric-box">
                    <div class="metric-value">{data['recall']:.4f}</div>
                    <div class="metric-label">Recall</div>
                </div>
                <div class="metric-box">
                    <div class="metric-value">{data['f1_score']:.4f}</div>
                    <div class="metric-label">F1-Score</div>
                </div>
                <div class="metric-box">
                    <div class="metric-value">{data['accuracy']:.4f}</div>
                    <div class="metric-label">Accuracy</div>
                </div>
                <div class="metric-box">
                    <div class="metric-value">{data['throughput_pps']/1e6:.2f}M</div>
                    <div class="metric-label">Packets/sec</div>
                </div>
                <div class="metric-box">
                    <div class="metric-value">{data['gpu_util']:.1f}%</div>
                    <div class="metric-label">GPU Utilization</div>
                </div>
            </div>
        </div>
    </div>
"""
    
    # Add summary slide
    best_f1_alg = max(available_algs, key=lambda a: alg_data_dict[a]['f1_score'])
    best_throughput_alg = max(available_algs, key=lambda a: alg_data_dict[a]['throughput_pps'])
    
    slides_html += f"""
    <!-- Slide: Summary -->
    <div class="slide">
        <h2>📊 Key Results Summary</h2>
        <div class="slide-content">
            <h3>Best Performance</h3>
            <ul style="font-size: 1.3em; line-height: 2.5;">
                <li><strong>Best F1-Score:</strong> {best_f1_alg} ({alg_data_dict[best_f1_alg]['f1_score']:.4f})</li>
                <li><strong>Highest Throughput:</strong> {best_throughput_alg} ({alg_data_dict[best_throughput_alg]['throughput_pps']/1e6:.2f}M pps)</li>
            </ul>
            <h3 style="margin-top: 40px;">GPU Acceleration Impact</h3>
            <p style="font-size: 1.2em;">Significant speedup for entropy-based detection and SVM inference</p>
            <h3 style="margin-top: 30px;">Blocking Effectiveness</h3>
            <p style="font-size: 1.2em;">High attack traffic blocking rates with minimal collateral damage</p>
        </div>
    </div>
    
    <!-- Slide: Conclusion -->
    <div class="slide">
        <h2>✅ Conclusions</h2>
        <div class="slide-content">
            <h3>Achievements</h3>
            <ul style="font-size: 1.3em; line-height: 2.5;">
                <li>✓ High-throughput processing (millions of packets/sec)</li>
                <li>✓ GPU acceleration enables real-time analysis</li>
                <li>✓ Multiple detection algorithms for comprehensive protection</li>
                <li>✓ Effective blocking mechanisms with low false positives</li>
            </ul>
            <h3 style="margin-top: 40px;">Thank You!</h3>
            <p style="font-size: 1.2em; margin-top: 20px;">Questions?</p>
        </div>
    </div>
</body>
<script>
    let currentSlide = 0;
    const slides = document.querySelectorAll('.slide');
    
    function showSlide(n) {{
        slides[currentSlide].classList.remove('active');
        currentSlide = (n + slides.length) % slides.length;
        slides[currentSlide].classList.add('active');
    }}
    
    function nextSlide() {{ showSlide(currentSlide + 1); }}
    function prevSlide() {{ showSlide(currentSlide - 1); }}
    
    document.addEventListener('keydown', (e) => {{
        if (e.key === 'ArrowRight') nextSlide();
        if (e.key === 'ArrowLeft') prevSlide();
    }});
</script>
<div class="nav">
    <button onclick="prevSlide()">← Previous</button>
    <button onclick="nextSlide()">Next →</button>
</div>
</html>
"""
    
    slides_file = f"{output_dir}/presentation_slides.html"
    with open(slides_file, 'w', encoding='utf-8') as f:
        f.write(slides_html)
    
    print(f"✓ Presentation slides saved to {slides_file}")

def generate_summary_report(metrics_data, output_dir="presentation"):
    """Generate comprehensive summary report"""
    os.makedirs(output_dir, exist_ok=True)
    
    if 'csv' not in metrics_data:
        print("No CSV data available for report")
        return
    
    df = metrics_data['csv']
    json_data = metrics_data.get('json', {})
    
    algorithms = ['Entropy', 'CUSUM', 'SVM', 'Combined']
    available_algs = [alg for alg in algorithms if alg in df['Algorithm'].values]
    
    report = f"""
{'='*80}
HIGH-RATE NETWORK TRAFFIC ANALYZER FOR EARLY DDOS DETECTION AND MITIGATION
Performance Summary Report
{'='*80}

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

EXECUTIVE SUMMARY
{'-'*80}
This report presents comprehensive performance analysis of a GPU-accelerated DDoS 
detection system implementing three detection algorithms (Entropy, CUSUM, SVM) 
with blocking mechanisms (RTBH, ACL).

SYSTEM CONFIGURATION
{'-'*80}
Platform: GPU-Accelerated (NVIDIA RTX 3050)
Framework: OpenCL 3.0
Dataset: CIC-DDoS2019
Algorithms Tested: {', '.join(available_algs)}

DETECTION ACCURACY RESULTS
{'-'*80}
"""
    
    for alg in available_algs:
        alg_row = df[df['Algorithm'] == alg].iloc[0]
        report += f"""
{alg} Detection Algorithm:
  Precision:        {alg_row.get('Precision', 0):.4f}
  Recall:           {alg_row.get('Recall', 0):.4f}
  F1-Score:         {alg_row.get('F1-Score', 0):.4f}
  Accuracy:         {alg_row.get('Accuracy', 0):.4f}
  False Positive Rate: {alg_row.get('FPR', 0):.4f}
"""
    
    report += f"""
PERFORMANCE METRICS
{'-'*80}
"""
    
    for alg in available_algs:
        alg_row = df[df['Algorithm'] == alg].iloc[0]
        report += f"""
{alg}:
  Throughput:       {alg_row.get('Packets/sec', 0)/1e6:.2f} Million packets/sec
  Network Throughput: {alg_row.get('Gbps', 0):.2f} Gbps
  GPU Utilization: {alg_row.get('GPU_Util%', 0):.2f}%
"""
    
    report += f"""
BLOCKING EFFECTIVENESS
{'-'*80}
"""
    
    for alg in available_algs:
        alg_row = df[df['Algorithm'] == alg].iloc[0]
        report += f"""
{alg}:
  Attack Traffic Blocked: {alg_row.get('Attack_Block%', 0):.2f}%
  Collateral Damage:      {alg_row.get('Collateral_Damage%', 0):.2f}%
"""
    
    # Find best performing algorithms
    best_f1_alg = max(available_algs, key=lambda a: df[df['Algorithm'] == a]['F1-Score'].iloc[0])
    best_throughput_alg = max(available_algs, key=lambda a: df[df['Algorithm'] == a]['Packets/sec'].iloc[0])
    
    report += f"""
KEY FINDINGS
{'-'*80}
• Best F1-Score: {best_f1_alg} ({df[df['Algorithm'] == best_f1_alg]['F1-Score'].iloc[0]:.4f})
• Highest Throughput: {best_throughput_alg} ({df[df['Algorithm'] == best_throughput_alg]['Packets/sec'].iloc[0]/1e6:.2f}M pps)
• GPU acceleration provides significant performance improvements
• Multiple detection algorithms enable comprehensive protection

{'='*80}
"""
    
    report_file = f"{output_dir}/summary_report.txt"
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(report)
    
    print(f"✓ Summary report saved to {report_file}")

def main():
    """Main function to generate all presentation materials"""
    print("="*80)
    print("DDoS Detection System - Presentation Generator")
    print("="*80)
    print()
    
    # Create output directories
    os.makedirs("presentation/plots", exist_ok=True)
    
    # Load metrics data
    print("Loading metrics data...")
    metrics_data = load_metrics("results")
    
    if not metrics_data or 'csv' not in metrics_data:
        print("ERROR: No metrics data found. Please run experiments first.")
        print("Expected file: results/detection_metrics.csv")
        return 1
    
    print(f"✓ Metrics data loaded successfully")
    print()
    
    # Generate all visualizations
    print("Generating visualizations...")
    try:
        plot_comprehensive_detection_metrics(metrics_data)
        plot_performance_comparison(metrics_data)
        plot_algorithm_radar_chart(metrics_data)
        plot_roc_comparison(metrics_data)
        print()
    except Exception as e:
        print(f"Warning: Error generating some plots: {e}")
        print()
    
    # Generate HTML dashboard
    print("Generating HTML dashboard...")
    try:
        generate_html_dashboard(metrics_data)
        print()
    except Exception as e:
        print(f"Warning: Error generating dashboard: {e}")
        print()
    
    # Generate presentation slides
    print("Generating presentation slides...")
    try:
        generate_presentation_slides(metrics_data)
        print()
    except Exception as e:
        print(f"Warning: Error generating slides: {e}")
        print()
    
    # Generate summary report
    print("Generating summary report...")
    try:
        generate_summary_report(metrics_data)
        print()
    except Exception as e:
        print(f"Warning: Error generating report: {e}")
        print()
    
    print("="*80)
    print("Presentation generation complete!")
    print("="*80)
    print()
    print("Generated files:")
    print("  • presentation/plots/comprehensive_detection_metrics.png")
    print("  • presentation/plots/performance_comparison.png")
    print("  • presentation/plots/algorithm_radar_chart.png")
    print("  • presentation/plots/roc_comparison.png")
    print("  • presentation/dashboard.html")
    print("  • presentation/presentation_slides.html")
    print("  • presentation/summary_report.txt")
    print()
    print("To view the dashboard, open: presentation/dashboard.html")
    print("To view the slides, open: presentation/presentation_slides.html")
    print("  (Use arrow keys or buttons to navigate slides)")
    print()
    
    return 0

if __name__ == "__main__":
    exit(main())