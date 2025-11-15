@echo off
REM Experiment Script for DDoS Detection System
REM Runs various experiments and collects performance metrics

echo === DDoS Detection System - Experiment Runner ===
echo.

REM Check if dataset exists
if not exist "data\CSV-01-12\01-12\DrDoS_DNS.csv" (
    echo ERROR: Dataset not found at data\CSV-01-12\01-12\DrDoS_DNS.csv
    echo Please download CIC-DDoS2019 dataset and place it in the data\ directory
    echo Download from: https://www.unb.ca/cic/datasets/ddos-2019.html
    pause
    exit /b 1
)

REM Create results directory
if not exist "results" mkdir results
if not exist "results\plots" mkdir results\plots

echo Starting experiments...
echo.

REM Experiment 1: Full system test
echo === Experiment 1: Full System Test ===
echo Running all detection algorithms with GPU acceleration...
ddos_detector.exe -d data\CSV-01-12\01-12\DrDoS_DNS.csv -r results\ -v
if %errorlevel% neq 0 (
    echo ERROR: Full system test failed
    pause
    exit /b 1
)

REM Experiment 2: CPU-only comparison
echo.
echo === Experiment 2: CPU-Only Comparison ===
echo Running all detection algorithms without GPU acceleration...
ddos_detector.exe -d data\CSV-01-12\01-12\DrDoS_DNS.csv -r results\cpu_only\ --no-gpu -v
if %errorlevel% neq 0 (
    echo ERROR: CPU-only test failed
    pause
    exit /b 1
)

REM Experiment 3: Individual algorithm tests
echo.
echo === Experiment 3: Individual Algorithm Tests ===

echo Running entropy detection only...
ddos_detector.exe -d data\CSV-01-12\01-12\DrDoS_DNS.csv -r results\entropy_only\ --no-cusum --no-svm --no-rtbh --no-acl -v

echo Running CUSUM detection only...
ddos_detector.exe -d data\CSV-01-12\01-12\DrDoS_DNS.csv -r results\cusum_only\ --no-entropy --no-svm --no-rtbh --no-acl -v

echo Running SVM detection only...
ddos_detector.exe -d data\CSV-01-12\01-12\DrDoS_DNS.csv -r results\svm_only\ --no-entropy --no-cusum --no-rtbh --no-acl -v

REM Experiment 4: Blocking mechanism tests
echo.
echo === Experiment 4: Blocking Mechanism Tests ===

echo Running RTBH blocking only...
ddos_detector.exe -d data\CSV-01-12\01-12\DrDoS_DNS.csv -r results\rtbh_only\ --no-entropy --no-cusum --no-svm --no-acl -v

echo Running ACL filtering only...
ddos_detector.exe -d data\CSV-01-12\01-12\DrDoS_DNS.csv -r results\acl_only\ --no-entropy --no-cusum --no-svm --no-rtbh -v

REM Run analysis script
echo.
echo === Running Analysis Script ===
python experiments\analyze_results.py

echo.
echo === Experiments Completed ===
echo Check the results\ directory for:
echo   - detection_metrics.csv (overall metrics)
echo   - detection_metrics.json (detailed metrics)
echo   - plots\ (generated graphs)
echo   - Individual experiment results in subdirectories
echo.
pause
