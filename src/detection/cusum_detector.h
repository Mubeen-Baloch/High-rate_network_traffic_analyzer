#ifndef CUSUM_DETECTOR_H
#define CUSUM_DETECTOR_H

#include "traffic_parser.h"
#include "metrics.h"

// CUSUM detection configuration
typedef struct {
    float threshold;            // Detection threshold
    float drift_parameter;     // Drift parameter (k)
    float smoothing_factor;    // Smoothing factor for baseline
    uint32_t min_samples;      // Minimum samples for detection
    uint32_t window_size;      // Window size for baseline calculation
} cusum_config_t;

// CUSUM detection state
typedef struct {
    cusum_config_t config;
    
    // CUSUM variables
    float *baseline_values;    // Baseline values for each metric
    float *cusum_values;       // Current CUSUM values
    float *drift_values;       // Drift values
    uint32_t *sample_counts;   // Sample counts
    
    // Metrics being monitored
    float packet_rate_baseline;
    float byte_rate_baseline;
    float connection_rate_baseline;
    float packet_size_baseline;
    
    float packet_rate_cusum;
    float byte_rate_cusum;
    float connection_rate_cusum;
    float packet_size_cusum;
    
    // State variables
    uint32_t sample_count;
    uint64_t last_update_time;
    uint32_t detection_count;
    
    // Metrics
    algorithm_metrics_t *metrics;
} cusum_detector_t;

// Function declarations
int cusum_detector_init(cusum_detector_t *detector, const cusum_config_t *config, 
                       algorithm_metrics_t *metrics);
void cusum_detector_cleanup(cusum_detector_t *detector);

// Main detection functions
int cusum_detector_process_flows(cusum_detector_t *detector, flow_collection_t *flows);
int cusum_detector_process_window(cusum_detector_t *detector, time_window_t *window);
int cusum_detector_update_baseline(cusum_detector_t *detector, time_window_t *window);

// CUSUM algorithm functions
float cusum_calculate_statistic(float current_value, float baseline, float drift);
int cusum_detect_change(float cusum_value, float threshold);
void cusum_update_baseline(float *baseline, float new_value, float smoothing_factor);

// Feature extraction functions
float cusum_extract_packet_rate(time_window_t *window);
float cusum_extract_byte_rate(time_window_t *window);
float cusum_extract_connection_rate(time_window_t *window);
float cusum_extract_packet_size_variance(time_window_t *window);

// Configuration functions
void cusum_detector_get_default_config(cusum_config_t *config);
void cusum_detector_set_config(cusum_detector_t *detector, const cusum_config_t *config);

// Analysis functions
int cusum_detector_analyze_results(cusum_detector_t *detector, time_window_t *window);
void cusum_detector_print_statistics(cusum_detector_t *detector);

#endif // CUSUM_DETECTOR_H
