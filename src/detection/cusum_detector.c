#include "cusum_detector.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

void cusum_detector_get_default_config(cusum_config_t *config) {
    config->threshold = 1.0f;           // Detection threshold (lowered for sensitivity)
    config->drift_parameter = 0.1f;     // Drift parameter (lowered)
    config->smoothing_factor = 0.3f;   // Smoothing factor (increased)
    config->min_samples = 1;            // Minimum samples (lowered for small datasets)
    config->window_size = 100;          // Window size for baseline
}

int cusum_detector_init(cusum_detector_t *detector, const cusum_config_t *config, 
                       algorithm_metrics_t *metrics) {
    memset(detector, 0, sizeof(cusum_detector_t));
    
    detector->metrics = metrics;
    
    if (config) {
        detector->config = *config;
    } else {
        cusum_detector_get_default_config(&detector->config);
    }
    
    // Initialize CUSUM arrays
    detector->baseline_values = (float*)malloc(4 * sizeof(float));
    detector->cusum_values = (float*)malloc(4 * sizeof(float));
    detector->drift_values = (float*)malloc(4 * sizeof(float));
    detector->sample_counts = (uint32_t*)malloc(4 * sizeof(uint32_t));
    
    if (!detector->baseline_values || !detector->cusum_values || 
        !detector->drift_values || !detector->sample_counts) {
        fprintf(stderr, "Failed to allocate CUSUM arrays\n");
        cusum_detector_cleanup(detector);
        return -1;
    }
    
    // Initialize values
    detector->packet_rate_baseline = 0.0f;
    detector->byte_rate_baseline = 0.0f;
    detector->connection_rate_baseline = 0.0f;
    detector->packet_size_baseline = 0.0f;
    
    detector->packet_rate_cusum = 0.0f;
    detector->byte_rate_cusum = 0.0f;
    detector->connection_rate_cusum = 0.0f;
    detector->packet_size_cusum = 0.0f;
    
    detector->sample_count = 0;
    detector->detection_count = 0;
    
    printf("CUSUM detector initialized successfully\n");
    return 0;
}

void cusum_detector_cleanup(cusum_detector_t *detector) {
    if (detector->baseline_values) free(detector->baseline_values);
    if (detector->cusum_values) free(detector->cusum_values);
    if (detector->drift_values) free(detector->drift_values);
    if (detector->sample_counts) free(detector->sample_counts);
    
    memset(detector, 0, sizeof(cusum_detector_t));
}

int cusum_detector_process_flows(cusum_detector_t *detector, flow_collection_t *flows) {
    if (!detector || !flows) return -1;
    
    uint64_t start_time = metrics_get_current_time_us();
    
    // Create time windows
    time_window_t *windows;
    size_t window_count;
    
    if (create_time_windows(flows, &windows, &window_count, 1000) != 0) { // 1 second windows
        fprintf(stderr, "Failed to create time windows\n");
        return -1;
    }
    
    printf("Processing %zu flows in %zu time windows with CUSUM\n", flows->count, window_count);
    
    // Process each window
    for (size_t i = 0; i < window_count; i++) {
        if (windows[i].flow_count > 0) {
            if (cusum_detector_process_window(detector, &windows[i]) != 0) {
                fprintf(stderr, "Failed to process window %zu\n", i);
                free_time_windows(windows, window_count);
                return -1;
            }
        }
    }
    
    uint64_t end_time = metrics_get_current_time_us();
    if (detector->metrics) {
        metrics_record_processing_time(detector->metrics, end_time - start_time);
    }
    
    free_time_windows(windows, window_count);
    return 0;
}

int cusum_detector_process_window(cusum_detector_t *detector, time_window_t *window) {
    if (!detector || !window) return -1;
    
    // Extract features
    float packet_rate = cusum_extract_packet_rate(window);
    float byte_rate = cusum_extract_byte_rate(window);
    float connection_rate = cusum_extract_connection_rate(window);
    float packet_size_var = cusum_extract_packet_size_variance(window);
    
    // Update baselines if we have enough samples
    if (detector->sample_count >= detector->config.min_samples) {
        cusum_update_baseline(&detector->packet_rate_baseline, packet_rate, 
                             detector->config.smoothing_factor);
        cusum_update_baseline(&detector->byte_rate_baseline, byte_rate, 
                             detector->config.smoothing_factor);
        cusum_update_baseline(&detector->connection_rate_baseline, connection_rate, 
                             detector->config.smoothing_factor);
        cusum_update_baseline(&detector->packet_size_baseline, packet_size_var, 
                             detector->config.smoothing_factor);
    } else {
        // Initialize baselines
        detector->packet_rate_baseline = packet_rate;
        detector->byte_rate_baseline = byte_rate;
        detector->connection_rate_baseline = connection_rate;
        detector->packet_size_baseline = packet_size_var;
    }
    
    // Calculate CUSUM statistics
    detector->packet_rate_cusum = cusum_calculate_statistic(packet_rate, 
                                                           detector->packet_rate_baseline, 
                                                           detector->config.drift_parameter);
    detector->byte_rate_cusum = cusum_calculate_statistic(byte_rate, 
                                                        detector->byte_rate_baseline, 
                                                        detector->config.drift_parameter);
    detector->connection_rate_cusum = cusum_calculate_statistic(connection_rate, 
                                                               detector->connection_rate_baseline, 
                                                               detector->config.drift_parameter);
    detector->packet_size_cusum = cusum_calculate_statistic(packet_size_var, 
                                                           detector->packet_size_baseline, 
                                                           detector->config.drift_parameter);
    
    // Detect changes
    int packet_rate_change = cusum_detect_change(detector->packet_rate_cusum, 
                                               detector->config.threshold);
    int byte_rate_change = cusum_detect_change(detector->byte_rate_cusum, 
                                             detector->config.threshold);
    int connection_rate_change = cusum_detect_change(detector->connection_rate_cusum, 
                                                    detector->config.threshold);
    int packet_size_change = cusum_detect_change(detector->packet_size_cusum, 
                                                detector->config.threshold);
    
    // Determine if attack is detected
    int attack_detected = (packet_rate_change || byte_rate_change || 
                          connection_rate_change || packet_size_change);
    
    if (attack_detected) {
        detector->detection_count++;
        printf("CUSUM Detection: ATTACK detected in window\n");
        printf("  Packet Rate CUSUM: %.4f (change: %s)\n", 
               detector->packet_rate_cusum, packet_rate_change ? "YES" : "NO");
        printf("  Byte Rate CUSUM: %.4f (change: %s)\n", 
               detector->byte_rate_cusum, byte_rate_change ? "YES" : "NO");
        printf("  Connection Rate CUSUM: %.4f (change: %s)\n", 
               detector->connection_rate_cusum, connection_rate_change ? "YES" : "NO");
        printf("  Packet Size CUSUM: %.4f (change: %s)\n", 
               detector->packet_size_cusum, packet_size_change ? "YES" : "NO");
    }
    
    // Update metrics
    if (detector->metrics) {
        // Record performance metrics
        uint64_t total_packets = 0;
        uint64_t total_bytes = 0;
        for (size_t i = 0; i < window->flow_count; i++) {
            total_packets += window->flows[i].total_fwd_packets + window->flows[i].total_bwd_packets;
            total_bytes += window->flows[i].total_fwd_bytes + window->flows[i].total_bwd_bytes;
        }
        
        detector->metrics->performance.total_packets_processed += total_packets;
        detector->metrics->performance.total_bytes_processed += total_bytes;
        detector->metrics->performance.total_flows_processed += window->flow_count;
        
        // Record detection and blocking metrics for each flow
        for (size_t i = 0; i < window->flow_count; i++) {
            int is_attack = is_attack_flow(&window->flows[i]);
            metrics_record_detection(detector->metrics, is_attack, attack_detected);
            
            // Record blocking metrics (simulate blocking when attack detected)
            uint32_t flow_packets = window->flows[i].total_fwd_packets + window->flows[i].total_bwd_packets;
            uint32_t flow_bytes = window->flows[i].total_fwd_bytes + window->flows[i].total_bwd_bytes;
            int was_blocked = attack_detected ? 1 : 0; // Block if attack detected
            
            metrics_record_blocking(detector->metrics, is_attack, was_blocked, flow_packets, flow_bytes);
        }
    }
    
    detector->sample_count++;
    return 0;
}

float cusum_calculate_statistic(float current_value, float baseline, float drift) {
    float deviation = current_value - baseline;
    float drift_adjusted = deviation - drift;
    
    // CUSUM: S_n = max(0, S_{n-1} + deviation - drift)
    // For simplicity, we'll use the current deviation
    return fabsf(drift_adjusted);
}

int cusum_detect_change(float cusum_value, float threshold) {
    return (cusum_value > threshold) ? 1 : 0;
}

void cusum_update_baseline(float *baseline, float new_value, float smoothing_factor) {
    *baseline = (*baseline * (1.0f - smoothing_factor)) + (new_value * smoothing_factor);
}

float cusum_extract_packet_rate(time_window_t *window) {
    if (window->flow_count == 0) return 0.0f;
    
    uint32_t total_packets = 0;
    for (size_t i = 0; i < window->flow_count; i++) {
        total_packets += window->flows[i].total_fwd_packets + window->flows[i].total_bwd_packets;
    }
    
    // Calculate packets per second
    uint64_t window_duration_us = window->end_time - window->start_time;
    float window_duration_sec = window_duration_us / 1000000.0f;
    
    return (window_duration_sec > 0) ? (float)total_packets / window_duration_sec : 0.0f;
}

float cusum_extract_byte_rate(time_window_t *window) {
    if (window->flow_count == 0) return 0.0f;
    
    uint64_t total_bytes = 0;
    for (size_t i = 0; i < window->flow_count; i++) {
        total_bytes += window->flows[i].total_fwd_bytes + window->flows[i].total_bwd_bytes;
    }
    
    // Calculate bytes per second
    uint64_t window_duration_us = window->end_time - window->start_time;
    float window_duration_sec = window_duration_us / 1000000.0f;
    
    return (window_duration_sec > 0) ? (float)total_bytes / window_duration_sec : 0.0f;
}

float cusum_extract_connection_rate(time_window_t *window) {
    if (window->flow_count == 0) return 0.0f;
    
    // Calculate connections per second
    uint64_t window_duration_us = window->end_time - window->start_time;
    float window_duration_sec = window_duration_us / 1000000.0f;
    
    return (window_duration_sec > 0) ? (float)window->flow_count / window_duration_sec : 0.0f;
}

float cusum_extract_packet_size_variance(time_window_t *window) {
    if (window->flow_count == 0) return 0.0f;
    
    // Calculate packet size variance
    float sum = 0.0f;
    float sum_squares = 0.0f;
    uint32_t total_packets = 0;
    
    for (size_t i = 0; i < window->flow_count; i++) {
        uint32_t packets = window->flows[i].total_fwd_packets + window->flows[i].total_bwd_packets;
        uint64_t bytes = window->flows[i].total_fwd_bytes + window->flows[i].total_bwd_bytes;
        
        if (packets > 0) {
            float avg_packet_size = (float)bytes / (float)packets;
            sum += avg_packet_size * packets;
            sum_squares += avg_packet_size * avg_packet_size * packets;
            total_packets += packets;
        }
    }
    
    if (total_packets == 0) return 0.0f;
    
    float mean = sum / total_packets;
    float variance = (sum_squares / total_packets) - (mean * mean);
    
    return (variance > 0) ? sqrtf(variance) : 0.0f;
}

int cusum_detector_analyze_results(cusum_detector_t *detector, time_window_t *window) {
    if (!detector || !window) return -1;
    
    // Analysis is done in process_window
    return 0;
}

void cusum_detector_print_statistics(cusum_detector_t *detector) {
    printf("\n=== CUSUM Detector Statistics ===\n");
    printf("Configuration:\n");
    printf("  Threshold: %.2f\n", detector->config.threshold);
    printf("  Drift Parameter: %.2f\n", detector->config.drift_parameter);
    printf("  Smoothing Factor: %.2f\n", detector->config.smoothing_factor);
    printf("  Min Samples: %u\n", detector->config.min_samples);
    printf("  Window Size: %u\n", detector->config.window_size);
    
    printf("Current State:\n");
    printf("  Sample Count: %u\n", detector->sample_count);
    printf("  Detection Count: %u\n", detector->detection_count);
    printf("  Packet Rate Baseline: %.2f\n", detector->packet_rate_baseline);
    printf("  Byte Rate Baseline: %.2f\n", detector->byte_rate_baseline);
    printf("  Connection Rate Baseline: %.2f\n", detector->connection_rate_baseline);
    printf("  Packet Size Baseline: %.2f\n", detector->packet_size_baseline);
    
    printf("Current CUSUM Values:\n");
    printf("  Packet Rate CUSUM: %.4f\n", detector->packet_rate_cusum);
    printf("  Byte Rate CUSUM: %.4f\n", detector->byte_rate_cusum);
    printf("  Connection Rate CUSUM: %.4f\n", detector->connection_rate_cusum);
    printf("  Packet Size CUSUM: %.4f\n", detector->packet_size_cusum);
}

void cusum_detector_set_config(cusum_detector_t *detector, const cusum_config_t *config) {
    if (detector && config) {
        detector->config = *config;
    }
}
