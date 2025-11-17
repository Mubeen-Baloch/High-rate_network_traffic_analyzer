#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Include all components
#include "traffic_parser.h"
#include "opencl_manager.h"
#include "metrics.h"
#include "detection/entropy_detector.h"
#include "detection/cusum_detector.h"
#include "detection/svm_detector.h"
#include "blocking/rtbh_simulator.h"
#include "blocking/acl_filter.h"

// System configuration
typedef struct {
    char dataset_path[256];
    char results_dir[256];
    int enable_entropy;
    int enable_cusum;
    int enable_svm;
    int enable_rtbh;
    int enable_acl;
    int use_gpu;
    int verbose;
} system_config_t;

// Global system state
typedef struct {
    system_config_t config;
    opencl_context_t opencl_ctx;
    system_metrics_t metrics;
    
    // Detection algorithms
    entropy_detector_t entropy_detector;
    cusum_detector_t cusum_detector;
    svm_detector_t svm_detector;
    
    // Blocking mechanisms
    rtbh_simulator_t rtbh_simulator;
    acl_filter_t acl_filter;
    
    // Data
    flow_collection_t flows;
} ddos_system_t;

// Function declarations
void print_usage(const char *program_name);
int parse_arguments(int argc, char *argv[], system_config_t *config);
int system_init(ddos_system_t *system);
void system_cleanup(ddos_system_t *system);
int system_run_experiment(ddos_system_t *system);
int system_load_dataset(ddos_system_t *system);
int system_run_detection(ddos_system_t *system);
int system_run_blocking(ddos_system_t *system);
void system_print_results(ddos_system_t *system);

int main(int argc, char *argv[]) {
    ddos_system_t system;
    int result = 0;
    
    printf("=== High-Rate DDoS Detection System (OpenCL/GPU) ===\n");
    printf("Parallel and Distributed Computing Project\n\n");
    
    // Parse command line arguments
    if (parse_arguments(argc, argv, &system.config) != 0) {
        print_usage(argv[0]);
        return 1;
    }
    
    // Initialize system
    if (system_init(&system) != 0) {
        fprintf(stderr, "Failed to initialize system\n");
        return 1;
    }
    
    // Run experiment
    if (system_run_experiment(&system) != 0) {
        fprintf(stderr, "Experiment failed\n");
        result = 1;
    }
    
    // Cleanup
    system_cleanup(&system);
    
    printf("\nExperiment completed. Check results/ directory for detailed metrics.\n");
    return result;
}

void print_usage(const char *program_name) {
    printf("Usage: %s [OPTIONS]\n", program_name);
    printf("\nOptions:\n");
    printf("  -d, --dataset PATH     Path to CIC-DDoS2019 CSV file (required)\n");
    printf("  -r, --results DIR      Results directory (default: results/)\n");
    printf("  -e, --entropy          Enable entropy-based detection (default: yes)\n");
    printf("  -c, --cusum            Enable CUSUM detection (default: yes)\n");
    printf("  -s, --svm              Enable SVM detection (default: yes)\n");
    printf("  -b, --rtbh             Enable RTBH blocking (default: yes)\n");
    printf("  -a, --acl              Enable ACL filtering (default: yes)\n");
    printf("  -g, --gpu              Enable GPU acceleration (default: yes)\n");
    printf("  -v, --verbose          Enable verbose output\n");
    printf("  -h, --help             Show this help message\n");
    printf("\nExamples:\n");
    printf("  %s -d data/cic-ddos2019.csv\n", program_name);
    printf("  %s -d data/cic-ddos2019.csv -r results/ -v\n", program_name);
    printf("  %s -d data/cic-ddos2019.csv --no-gpu --no-svm\n", program_name);
}

int parse_arguments(int argc, char *argv[], system_config_t *config) {
    // Set defaults
    strcpy(config->dataset_path, "");
    strcpy(config->results_dir, "results/");
    config->enable_entropy = 1;
    config->enable_cusum = 1;
    config->enable_svm = 1;
    config->enable_rtbh = 1;
    config->enable_acl = 1;
    config->use_gpu = 1;
    config->verbose = 0;
    
    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--dataset") == 0) {
            if (i + 1 < argc) {
                strcpy(config->dataset_path, argv[++i]);
            } else {
                fprintf(stderr, "Error: Dataset path required\n");
                return -1;
            }
        } else if (strcmp(argv[i], "-r") == 0 || strcmp(argv[i], "--results") == 0) {
            if (i + 1 < argc) {
                strcpy(config->results_dir, argv[++i]);
            } else {
                fprintf(stderr, "Error: Results directory required\n");
                return -1;
            }
        } else if (strcmp(argv[i], "-e") == 0 || strcmp(argv[i], "--entropy") == 0) {
            config->enable_entropy = 1;
        } else if (strcmp(argv[i], "--no-entropy") == 0) {
            config->enable_entropy = 0;
        } else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--cusum") == 0) {
            config->enable_cusum = 1;
        } else if (strcmp(argv[i], "--no-cusum") == 0) {
            config->enable_cusum = 0;
        } else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--svm") == 0) {
            config->enable_svm = 1;
        } else if (strcmp(argv[i], "--no-svm") == 0) {
            config->enable_svm = 0;
        } else if (strcmp(argv[i], "-b") == 0 || strcmp(argv[i], "--rtbh") == 0) {
            config->enable_rtbh = 1;
        } else if (strcmp(argv[i], "--no-rtbh") == 0) {
            config->enable_rtbh = 0;
        } else if (strcmp(argv[i], "-a") == 0 || strcmp(argv[i], "--acl") == 0) {
            config->enable_acl = 1;
        } else if (strcmp(argv[i], "--no-acl") == 0) {
            config->enable_acl = 0;
        } else if (strcmp(argv[i], "-g") == 0 || strcmp(argv[i], "--gpu") == 0) {
            config->use_gpu = 1;
        } else if (strcmp(argv[i], "--no-gpu") == 0) {
            config->use_gpu = 0;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            config->verbose = 1;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            return -1; // Will trigger help display
        } else {
            fprintf(stderr, "Error: Unknown option %s\n", argv[i]);
            return -1;
        }
    }
    
    // Validate required arguments
    if (strlen(config->dataset_path) == 0) {
        fprintf(stderr, "Error: Dataset path is required\n");
        return -1;
    }
    
    return 0;
}

int system_init(ddos_system_t *system) {
    printf("Initializing DDoS detection system...\n");
    
    // Initialize metrics
    metrics_init(&system->metrics);
    
    // Initialize OpenCL if GPU is enabled
    if (system->config.use_gpu) {
        printf("Initializing OpenCL context...\n");
        if (opencl_init(&system->opencl_ctx) != 0) {
            fprintf(stderr, "Failed to initialize OpenCL, falling back to CPU-only mode\n");
            system->config.use_gpu = 0;
        } else {
            // Load OpenCL kernels
            if (opencl_load_kernels(&system->opencl_ctx, "kernels/combined_kernels.cl") != 0) {
                fprintf(stderr, "Failed to load OpenCL kernels\n");
                system->config.use_gpu = 0;
            }
        }
    }
    
    // Initialize detection algorithms
    if (system->config.enable_entropy) {
        printf("Initializing entropy detector...\n");
        entropy_config_t entropy_config;
        entropy_detector_get_default_config(&entropy_config);
        if (entropy_detector_init(&system->entropy_detector, 
                                 system->config.use_gpu ? &system->opencl_ctx : NULL,
                                 &entropy_config, &system->metrics.entropy_metrics) != 0) {
            fprintf(stderr, "Failed to initialize entropy detector\n");
            return -1;
        }
    }
    
    if (system->config.enable_cusum) {
        printf("Initializing CUSUM detector...\n");
        cusum_config_t cusum_config;
        cusum_detector_get_default_config(&cusum_config);
        if (cusum_detector_init(&system->cusum_detector, &cusum_config, 
                               &system->metrics.cusum_metrics) != 0) {
            fprintf(stderr, "Failed to initialize CUSUM detector\n");
            return -1;
        }
    }
    
    if (system->config.enable_svm) {
        printf("Initializing SVM detector...\n");
        svm_config_t svm_config;
        svm_detector_get_default_config(&svm_config);
        svm_config.use_gpu = system->config.use_gpu;
        if (svm_detector_init(&system->svm_detector, 
                             system->config.use_gpu ? &system->opencl_ctx : NULL,
                             &svm_config, &system->metrics.svm_metrics) != 0) {
            fprintf(stderr, "Failed to initialize SVM detector\n");
            return -1;
        }
    }
    
    // Initialize blocking mechanisms
    if (system->config.enable_rtbh) {
        printf("Initializing RTBH simulator...\n");
        rtbh_config_t rtbh_config;
        rtbh_get_default_config(&rtbh_config);
        if (rtbh_simulator_init(&system->rtbh_simulator, &rtbh_config, 
                               &system->metrics.entropy_metrics) != 0) {
            fprintf(stderr, "Failed to initialize RTBH simulator\n");
            return -1;
        }
    }
    
    if (system->config.enable_acl) {
        printf("Initializing ACL filter...\n");
        acl_config_t acl_config;
        acl_get_default_config(&acl_config);
        if (acl_filter_init(&system->acl_filter, &acl_config, 
                            &system->metrics.combined_metrics) != 0) {
            fprintf(stderr, "Failed to initialize ACL filter\n");
            return -1;
        }
    }
    
    printf("System initialization completed successfully\n");
    return 0;
}

void system_cleanup(ddos_system_t *system) {
    printf("Cleaning up system...\n");
    
    // Cleanup detection algorithms
    if (system->config.enable_entropy) {
        entropy_detector_cleanup(&system->entropy_detector);
    }
    if (system->config.enable_cusum) {
        cusum_detector_cleanup(&system->cusum_detector);
    }
    if (system->config.enable_svm) {
        svm_detector_cleanup(&system->svm_detector);
    }
    
    // Cleanup blocking mechanisms
    if (system->config.enable_rtbh) {
        rtbh_simulator_cleanup(&system->rtbh_simulator);
    }
    if (system->config.enable_acl) {
        acl_filter_cleanup(&system->acl_filter);
    }
    
    // Cleanup OpenCL
    if (system->config.use_gpu) {
        opencl_cleanup(&system->opencl_ctx);
    }
    
    // Cleanup data
    free_flow_collection(&system->flows);
    
    printf("System cleanup completed\n");
}

int system_run_experiment(ddos_system_t *system) {
    printf("\n=== Starting DDoS Detection Experiment ===\n");
    
    // Start experiment
    metrics_start_experiment(&system->metrics, "CIC-DDoS2019", "GPU-accelerated detection");
    
    // Load dataset
    if (system_load_dataset(system) != 0) {
        fprintf(stderr, "Failed to load dataset\n");
        return -1;
    }
    
    // Run detection algorithms
    if (system_run_detection(system) != 0) {
        fprintf(stderr, "Failed to run detection\n");
        return -1;
    }
    
    // Run blocking mechanisms
    if (system_run_blocking(system) != 0) {
        fprintf(stderr, "Failed to run blocking\n");
        return -1;
    }
    
    // End experiment
    metrics_end_experiment(&system->metrics);
    
    // Print results
    system_print_results(system);
    
    // Export results
    char csv_file[512], json_file[512];
    snprintf(csv_file, sizeof(csv_file), "%s/detection_metrics.csv", system->config.results_dir);
    snprintf(json_file, sizeof(json_file), "%s/detection_metrics.json", system->config.results_dir);
    
    metrics_export_csv(&system->metrics, csv_file);
    metrics_export_json(&system->metrics, json_file);
    
    printf("\nExperiment completed successfully\n");
    return 0;
}

int system_load_dataset(ddos_system_t *system) {
    printf("\nLoading dataset: %s\n", system->config.dataset_path);
    
    if (parse_cic_ddos_csv(system->config.dataset_path, &system->flows) != 0) {
        fprintf(stderr, "Failed to parse dataset\n");
        return -1;
    }
    
    printf("Dataset loaded successfully:\n");
    printf("  Total flows: %zu\n", system->flows.count);
    printf("  Time range: %llu - %llu\n", system->flows.start_time, system->flows.end_time);
    printf("  Duration: %.2f seconds\n", 
           (system->flows.end_time - system->flows.start_time) / 1000000.0);
    
    // Compute dataset (ground-truth) traffic metrics from the CSV time span
    {
        uint64_t duration_us = 0;
        if (system->flows.end_time > system->flows.start_time) {
            duration_us = system->flows.end_time - system->flows.start_time;
        }
        
        uint64_t total_packets = 0;
        uint64_t total_bytes = 0;
        for (size_t i = 0; i < system->flows.count; i++) {
            total_packets += (uint64_t)system->flows.flows[i].total_fwd_packets +
                             (uint64_t)system->flows.flows[i].total_bwd_packets;
            total_bytes += (uint64_t)system->flows.flows[i].total_fwd_bytes +
                           (uint64_t)system->flows.flows[i].total_bwd_bytes;
        }
        
        system->metrics.dataset.dataset_duration_us = duration_us;
        system->metrics.dataset.dataset_total_packets = total_packets;
        system->metrics.dataset.dataset_total_bytes = total_bytes;
        
        if (duration_us > 0) {
            double time_sec = duration_us / 1000000.0;
            system->metrics.dataset.dataset_packets_per_second = total_packets / time_sec;
            double bytes_per_second = total_bytes / time_sec;
            system->metrics.dataset.dataset_gbps = (bytes_per_second * 8.0) / (1024.0 * 1024.0 * 1024.0);
        } else {
            system->metrics.dataset.dataset_packets_per_second = 0.0;
            system->metrics.dataset.dataset_gbps = 0.0;
        }
    }
    
    return 0;
}

int system_run_detection(ddos_system_t *system) {
    printf("\n=== Running Detection Algorithms ===\n");
    
    // Run entropy detection
    if (system->config.enable_entropy) {
        printf("\nRunning entropy-based detection...\n");
        metrics_start_algorithm(&system->metrics.entropy_metrics, "Entropy");
        
        if (entropy_detector_process_flows(&system->entropy_detector, &system->flows) != 0) {
            fprintf(stderr, "Entropy detection failed\n");
            return -1;
        }
        
        metrics_end_algorithm(&system->metrics.entropy_metrics);
        entropy_detector_print_statistics(&system->entropy_detector);
    }
    
    // Run CUSUM detection
    if (system->config.enable_cusum) {
        printf("\nRunning CUSUM detection...\n");
        metrics_start_algorithm(&system->metrics.cusum_metrics, "CUSUM");
        
        if (cusum_detector_process_flows(&system->cusum_detector, &system->flows) != 0) {
            fprintf(stderr, "CUSUM detection failed\n");
            return -1;
        }
        
        metrics_end_algorithm(&system->metrics.cusum_metrics);
        cusum_detector_print_statistics(&system->cusum_detector);
    }
    
    // Run SVM detection
    if (system->config.enable_svm) {
        printf("\nRunning SVM detection...\n");
        metrics_start_algorithm(&system->metrics.svm_metrics, "SVM");
        
        if (svm_detector_process_flows(&system->svm_detector, &system->flows) != 0) {
            fprintf(stderr, "SVM detection failed\n");
            return -1;
        }
        
        metrics_end_algorithm(&system->metrics.svm_metrics);
        svm_detector_print_statistics(&system->svm_detector);
    }
    
    return 0;
}

int system_run_blocking(ddos_system_t *system) {
    printf("\n=== Running Blocking Mechanisms ===\n");
    
    // Run RTBH blocking
    if (system->config.enable_rtbh) {
        printf("\nRunning RTBH blocking...\n");
        
        if (rtbh_process_flows(&system->rtbh_simulator, &system->flows) != 0) {
            fprintf(stderr, "RTBH blocking failed\n");
            return -1;
        }
        
        rtbh_print_statistics(&system->rtbh_simulator);
    }
    
    // Run ACL filtering
    if (system->config.enable_acl) {
        printf("\nRunning ACL filtering...\n");
        
        if (acl_process_flows(&system->acl_filter, &system->flows) != 0) {
            fprintf(stderr, "ACL filtering failed\n");
            return -1;
        }
        
        acl_print_statistics(&system->acl_filter);
    }
    
    return 0;
}

void system_print_results(ddos_system_t *system) {
    printf("\n=== Experiment Results ===\n");
    
    // Try hardware GPU utilization (optional)
    float hw_util = 0.0f;
    if (opencl_query_gpu_utilization(&system->opencl_ctx, &hw_util) == 0) {
        printf("GPU Hardware Utilization (NVML): %.2f%%\n", hw_util);
    }
    
    // Calculate combined metrics from all algorithms
    metrics_calculate_combined_metrics(&system->metrics);
    
    // Print overall metrics
    metrics_print_summary(&system->metrics);
    
    // Compare algorithms
    metrics_compare_algorithms(&system->metrics);
    
    // Print blocking effectiveness
    if (system->config.enable_rtbh) {
        printf("\n=== RTBH Blocking Results ===\n");
        rtbh_print_statistics(&system->rtbh_simulator);
    }
    
    if (system->config.enable_acl) {
        printf("\n=== ACL Filtering Results ===\n");
        acl_print_statistics(&system->acl_filter);
    }
}
