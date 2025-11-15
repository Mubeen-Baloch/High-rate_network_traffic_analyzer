# Makefile for DDoS Detection System (OpenCL/GPU)
CC = gcc
CFLAGS = -Wall -Wextra -O3 -std=c99
INCLUDES = -I./src -I./src/detection -I./src/blocking
LIBS = -lOpenCL -lm

# Directories
SRC_DIR = src
DETECTION_DIR = src/detection
BLOCKING_DIR = src/blocking
KERNELS_DIR = kernels
BUILD_DIR = build

# Source files
MAIN_SRC = $(SRC_DIR)/main.c
PARSER_SRC = $(SRC_DIR)/traffic_parser.c
OPENCL_SRC = $(SRC_DIR)/opencl_manager.c
METRICS_SRC = $(SRC_DIR)/metrics.c

DETECTION_SRCS = $(DETECTION_DIR)/entropy_detector.c \
                $(DETECTION_DIR)/cusum_detector.c \
                $(DETECTION_DIR)/svm_detector.c

BLOCKING_SRCS = $(BLOCKING_DIR)/rtbh_simulator.c \
                $(BLOCKING_DIR)/acl_filter.c

ALL_SRCS = $(MAIN_SRC) $(PARSER_SRC) $(OPENCL_SRC) $(METRICS_SRC) \
           $(DETECTION_SRCS) $(BLOCKING_SRCS)

# Object files
OBJS = $(ALL_SRCS:.c=.o)

# Target executable
TARGET = ddos_detector.exe

# Default target
all: $(TARGET)

# Build executable
$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LIBS)

# Compile source files
%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Clean build files
clean:
	del /Q $(SRC_DIR)\*.o $(DETECTION_DIR)\*.o $(BLOCKING_DIR)\*.o $(TARGET) 2>nul || echo "Clean completed"

# Install dependencies (Windows)
install-deps:
	@echo "Installing dependencies..."
	@echo "1. Download and install NVIDIA CUDA Toolkit from:"
	@echo "   https://developer.nvidia.com/cuda-downloads"
	@echo "2. Install MinGW-w64 from:"
	@echo "   https://www.mingw-w64.org/downloads/"
	@echo "3. Install Python packages:"
	@echo "   pip install pandas numpy matplotlib scikit-learn"

# Download dataset
download-dataset:
	@echo "Please download CIC-DDoS2019 dataset from:"
	@echo "https://www.unb.ca/cic/datasets/ddos-2019.html"
	@echo "Place CSV files in the data/ directory"

# Run experiments
test: $(TARGET)
	@echo "Running experiments..."
	experiments\run_experiments.bat

# Help
help:
	@echo "Available targets:"
	@echo "  all           - Build the project"
	@echo "  clean         - Clean build files"
	@echo "  install-deps  - Show dependency installation instructions"
	@echo "  download-dataset - Show dataset download instructions"
	@echo "  test          - Run experiments"
	@echo "  help          - Show this help"

.PHONY: all clean install-deps download-dataset test help
