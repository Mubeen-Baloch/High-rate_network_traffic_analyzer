# Installation and Setup Guide

## Prerequisites

### Hardware Requirements
- Windows 10/11 (64-bit)
- NVIDIA GPU with OpenCL support (RTX 3050 tested)
- 8GB+ RAM
- 10GB+ free disk space

### Software Requirements
- NVIDIA CUDA Toolkit (includes OpenCL support)
- MinGW-w64 (for C compilation)
- Python 3.x with required packages

## Installation Steps

### ✅ 1. Python (Already Installed)
- **Status**: ✅ Python 3.13.3 installed and working
- **pip**: ✅ pip 25.0.1 installed and working

### ✅ 2. GCC Compiler (Already Installed)  
- **Status**: ✅ GCC 14.2.0 (MSYS2) installed and working
- **Note**: You have MSYS2 GCC which is perfect for this project

### 🔄 3. Install NVIDIA CUDA Toolkit (Required)
1. Download CUDA Toolkit from: https://developer.nvidia.com/cuda-downloads
2. Choose "Windows" → "x86_64" → "exe (local)"
3. Run the installer and follow the setup wizard
4. **Important**: During installation, make sure to check "Add CUDA to system PATH"
5. After installation, restart your terminal/PowerShell
6. Verify installation by running: `nvcc --version`

### ✅ 4. Python Dependencies (Already Installed)
- **Status**: ✅ All required packages installed
- **Packages**: pandas, numpy, matplotlib, scikit-learn, seaborn, joblib

### 🔄 5. Download CIC-DDoS2019 Dataset (Required)
1. Visit: https://www.unb.ca/cic/datasets/ddos-2019.html
2. Download the CSV files (look for "CIC-DDoS2019" dataset)
3. Place them in the `data/` directory
4. **Note**: The dataset is large (~2GB), so ensure you have enough disk space

### 6. Train SVM Model (Optional)
```bash
python experiments/train_svm.py --data data/cic-ddos2019.csv --output src/svm_model.h
```

## ✅ Current Installation Status

**Working Components:**
- ✅ Python 3.13.3 + pip 25.0.1
- ✅ GCC 14.2.0 (MSYS2) 
- ✅ Python dependencies (pandas, numpy, matplotlib, scikit-learn, seaborn, joblib)
- ✅ Basic C compilation and project structure

**Still Needed:**
- ✅ NVIDIA CUDA Toolkit 13.0.88 (INSTALLED AND WORKING!)
- ✅ CIC-DDoS2019 dataset (DOWNLOADED AND READY!)
  - Located in: `data/CSV-01-12/01-12/` and `data/CSV-03-11/03-11/`
  - Contains: Multiple DDoS attack types (DNS, LDAP, MSSQL, NTP, SNMP, SSDP, UDP, SYN, TFTP, etc.)

**Installation Complete:** ✅ All development tools ready!

## Building the Project

### Using Makefile
```bash
make clean
make
```

### Manual Compilation
```bash
gcc -Wall -Wextra -O3 -std=c99 -I./src -I./src/detection -I./src/blocking \
    src/*.c src/detection/*.c src/blocking/*.c \
    -o ddos_detector.exe -lOpenCL -lm
```

## Running Experiments

### Quick Start
```bash
# Run full system test
ddos_detector.exe -d data/cic-ddos2019.csv -v

# Run CPU-only comparison
ddos_detector.exe -d data/cic-ddos2019.csv --no-gpu -v

# Run specific algorithms only
ddos_detector.exe -d data/cic-ddos2019.csv --no-cusum --no-svm -v
```

### Batch Experiments
```bash
experiments/run_experiments.bat
```

### Analyze Results
```bash
python experiments/analyze_results.py
```

## Troubleshooting

### Common Issues

**OpenCL not found:**
- Ensure NVIDIA drivers are up to date
- Verify CUDA Toolkit installation
- Check GPU compatibility

**Compilation errors:**
- Verify MinGW-w64 installation
- Check PATH environment variable
- Ensure all source files are present

**Dataset not found:**
- Verify dataset is in `data/` directory
- Check file permissions
- Ensure CSV format is correct

**Python analysis errors:**
- Install required packages: `pip install -r requirements.txt`
- Check Python version (3.6+ required)

### Performance Optimization

**GPU Memory Issues:**
- Reduce batch size in detection algorithms
- Use CPU fallback for large datasets
- Monitor GPU memory usage

**Slow Performance:**
- Enable GPU acceleration: `--gpu`
- Use optimized compilation flags: `-O3`
- Check GPU utilization

## Project Structure

```
PDC Project/
├── src/                    # Source code
│   ├── main.c             # Main program
│   ├── *.c/h              # Core components
│   ├── detection/         # Detection algorithms
│   └── blocking/          # Blocking mechanisms
├── kernels/               # OpenCL kernels
├── data/                  # Dataset files
├── experiments/           # Experiment scripts
├── results/               # Output results
├── docs/                  # Documentation
├── Makefile              # Build configuration
└── README.md             # Project overview
```

## Support

For issues or questions:
1. Check this installation guide
2. Review the project documentation
3. Check system requirements
4. Verify all dependencies are installed correctly

## License

This project is for educational purposes as part of the Parallel and Distributed Computing course.
