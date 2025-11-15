# High-Rate DDoS Detection System (OpenCL/GPU)

A GPU-accelerated DDoS detection and mitigation system using OpenCL for parallel processing on NVIDIA GPUs.

## Project Overview

This project implements a high-performance DDoS detection system using:
- **OpenCL** for GPU acceleration on NVIDIA RTX 3050
- **Three detection algorithms**: Entropy-based, CUSUM statistical, and SVM machine learning
- **Two blocking methods**: RTBH simulation and ACL-based filtering
- **CIC-DDoS2019 dataset** for training and evaluation

## Architecture

```
src/
├── main.c                    # Main orchestration
├── traffic_parser.c/h        # Parse CIC-DDoS2019 CSV
├── opencl_manager.c/h        # OpenCL initialization
├── detection/
│   ├── entropy_detector.c/h  # Entropy calculation (GPU)
│   ├── cusum_detector.c/h    # CUSUM statistical detection
│   └── svm_detector.c/h      # SVM classifier
├── blocking/
│   ├── rtbh_simulator.c/h    # RTBH blocking simulation
│   └── acl_filter.c/h        # ACL-based filtering
└── metrics.c/h               # Performance metrics

kernels/
├── entropy_kernel.cl         # GPU kernel for entropy
├── feature_extraction.cl     # Feature extraction for ML
└── svm_inference.cl          # SVM classification kernel
```

## Requirements

- Windows 10/11 with NVIDIA GPU (RTX 3050 tested)
- NVIDIA CUDA Toolkit (includes OpenCL support)
- MinGW-w64 for C compilation
- Python 3.x with pandas, numpy, matplotlib

## Building

```bash
# Install dependencies (run as administrator)
# 1. Download and install NVIDIA CUDA Toolkit
# 2. Install MinGW-w64
# 3. Install Python packages: pip install pandas numpy matplotlib

# Build the project
make

# Run experiments
experiments\run_experiments.bat
```

## Usage

```bash
# Run DDoS detection on CIC-DDoS2019 dataset
./ddos_detector.exe data/cic-ddos2019.csv

# Run specific experiments
experiments\run_experiments.bat entropy
experiments\run_experiments.bat cusum
experiments\run_experiments.bat svm
experiments\run_experiments.bat all
```

## Performance Metrics

The system measures:
- **Detection Accuracy**: Precision, Recall, F1-Score, TPR, FPR
- **Timing**: Detection lead time, per-packet latency, 95th percentile
- **Throughput**: Packets/sec and Gbps processing rate
- **GPU Performance**: Kernel execution time, memory transfer overhead
- **Blocking Effectiveness**: Attack traffic blocked (%), collateral damage (%)

## Results

Results are saved in the `results/` directory:
- `detection_metrics.csv` - Accuracy metrics
- `timing_metrics.csv` - Latency and throughput data
- `gpu_performance.csv` - GPU utilization and kernel times
- `blocking_effectiveness.csv` - Blocking statistics
- `plots/` - Generated graphs and visualizations

## Dataset

Download CIC-DDoS2019 dataset from:
https://www.unb.ca/cic/datasets/ddos-2019.html

Place the CSV files in the `data/` directory.

## License

This project is for educational purposes as part of the Parallel and Distributed Computing course.
