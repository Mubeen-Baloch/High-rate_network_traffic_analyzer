#ifndef ENTROPY_DETECTOR_H
#define ENTROPY_DETECTOR_H

#include "traffic_parser.h"
#include "opencl_manager.h"
#include "metrics.h"

// Entropy detection configuration
typedef struct {
    float sensitivity;           // Detection sensitivity (0.0-1.0)
    uint64_t window_size_ms;    // Time window size in milliseconds
    uint32_t min_packets;       // Minimum packets for entropy calculation
    float entropy_threshold;    // Static threshold (if not using dynamic)
    int use_dynamic_threshold;  // Use dynamic threshold calculation
} entropy_config_t;

// Entropy detection state
typedef struct {
    entropy_config_t config;
    opencl_context_t *opencl_ctx;
    
    // GPU buffers
    opencl_buffer_t ip_buffer;
    opencl_buffer_t packet_count_buffer;
    opencl_buffer_t entropy_buffer;
    opencl_buffer_t threshold_buffer;
    opencl_buffer_t detection_buffer;
    
    // CPU data structures
    ip_stats_t *ip_stats;
    size_t ip_stats_count;
    uint32_t *unique_ips;
    uint32_t *packet_counts;
    float *entropy_values;
    uint32_t *detection_results;
    
    // State variables
    uint64_t last_window_time;
    uint32_t current_window_flows;
    float baseline_entropy;
    float current_threshold;
    
    // Metrics
    algorithm_metrics_t *metrics;
} entropy_detector_t;

// Function declarations
int entropy_detector_init(entropy_detector_t *detector, opencl_context_t *opencl_ctx, 
                         const entropy_config_t *config, algorithm_metrics_t *metrics);
void entropy_detector_cleanup(entropy_detector_t *detector);

// Main detection functions
int entropy_detector_process_flows(entropy_detector_t *detector, 
                                  flow_collection_t *flows);
int entropy_detector_process_window(entropy_detector_t *detector, 
                                   time_window_t *window);

// GPU-accelerated functions
int entropy_detector_calculate_entropy_gpu(entropy_detector_t *detector, 
                                          ip_stats_t *ip_stats, size_t count);
int entropy_detector_detect_attacks_gpu(entropy_detector_t *detector, 
                                       float *entropy_values, size_t count);

// CPU fallback functions
float entropy_detector_calculate_entropy_cpu(ip_stats_t *ip_stats, size_t count);
int entropy_detector_detect_attacks_cpu(entropy_detector_t *detector, 
                                       float *entropy_values, size_t count);

// Utility functions
int entropy_detector_build_ip_statistics(entropy_detector_t *detector, 
                                        time_window_t *window);
float entropy_detector_calculate_threshold(entropy_detector_t *detector, 
                                          float *entropy_values, size_t count);
void entropy_detector_update_baseline(entropy_detector_t *detector, 
                                     float current_entropy);

// Configuration functions
void entropy_detector_set_config(entropy_detector_t *detector, 
                                const entropy_config_t *config);
void entropy_detector_get_default_config(entropy_config_t *config);

// Analysis functions
int entropy_detector_analyze_results(entropy_detector_t *detector, 
                                    time_window_t *window, 
                                    uint32_t *detection_results);
void entropy_detector_print_statistics(entropy_detector_t *detector);

#endif // ENTROPY_DETECTOR_H
