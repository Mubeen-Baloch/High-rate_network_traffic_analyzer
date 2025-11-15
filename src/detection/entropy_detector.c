#include "entropy_detector.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

void entropy_detector_get_default_config(entropy_config_t *config) {
    config->sensitivity = 0.3f;           // Moderate sensitivity
    config->window_size_ms = 1000;        // 1 second windows
    config->min_packets = 100;             // Minimum packets for analysis
    config->entropy_threshold = 3.0f;      // Static threshold
    config->use_dynamic_threshold = 1;     // Use dynamic threshold
}

int entropy_detector_init(entropy_detector_t *detector, opencl_context_t *opencl_ctx, 
                         const entropy_config_t *config, algorithm_metrics_t *metrics) {
    memset(detector, 0, sizeof(entropy_detector_t));
    
    detector->opencl_ctx = opencl_ctx;
    detector->metrics = metrics;
    
    if (config) {
        detector->config = *config;
    } else {
        entropy_detector_get_default_config(&detector->config);
    }
    
    // Initialize GPU buffers
    size_t max_ips = 65536; // Maximum unique IPs per window
    
    if (opencl_create_buffer(opencl_ctx, &detector->ip_buffer, 
                            max_ips * sizeof(uint32_t), CL_MEM_READ_WRITE) != 0) {
        fprintf(stderr, "Failed to create IP buffer\n");
        return -1;
    }
    
    if (opencl_create_buffer(opencl_ctx, &detector->packet_count_buffer, 
                            max_ips * sizeof(uint32_t), CL_MEM_READ_WRITE) != 0) {
        fprintf(stderr, "Failed to create packet count buffer\n");
        opencl_release_buffer(&detector->ip_buffer);
        return -1;
    }
    
    if (opencl_create_buffer(opencl_ctx, &detector->entropy_buffer, 
                            max_ips * sizeof(float), CL_MEM_READ_WRITE) != 0) {
        fprintf(stderr, "Failed to create entropy buffer\n");
        opencl_release_buffer(&detector->ip_buffer);
        opencl_release_buffer(&detector->packet_count_buffer);
        return -1;
    }
    
    if (opencl_create_buffer(opencl_ctx, &detector->threshold_buffer, 
                            sizeof(float), CL_MEM_READ_WRITE) != 0) {
        fprintf(stderr, "Failed to create threshold buffer\n");
        opencl_release_buffer(&detector->ip_buffer);
        opencl_release_buffer(&detector->packet_count_buffer);
        opencl_release_buffer(&detector->entropy_buffer);
        return -1;
    }
    
    if (opencl_create_buffer(opencl_ctx, &detector->detection_buffer, 
                            max_ips * sizeof(uint32_t), CL_MEM_READ_WRITE) != 0) {
        fprintf(stderr, "Failed to create detection buffer\n");
        opencl_release_buffer(&detector->ip_buffer);
        opencl_release_buffer(&detector->packet_count_buffer);
        opencl_release_buffer(&detector->entropy_buffer);
        opencl_release_buffer(&detector->threshold_buffer);
        return -1;
    }
    
    // Initialize CPU arrays
    detector->unique_ips = (uint32_t*)malloc(max_ips * sizeof(uint32_t));
    detector->packet_counts = (uint32_t*)malloc(max_ips * sizeof(uint32_t));
    detector->entropy_values = (float*)malloc(max_ips * sizeof(float));
    detector->detection_results = (uint32_t*)malloc(max_ips * sizeof(uint32_t));
    
    if (!detector->unique_ips || !detector->packet_counts || 
        !detector->entropy_values || !detector->detection_results) {
        fprintf(stderr, "Failed to allocate CPU arrays\n");
        entropy_detector_cleanup(detector);
        return -1;
    }
    
    detector->baseline_entropy = 0.0f;
    detector->current_threshold = detector->config.entropy_threshold;
    
    printf("Entropy detector initialized successfully\n");
    return 0;
}

void entropy_detector_cleanup(entropy_detector_t *detector) {
    // Release GPU buffers
    opencl_release_buffer(&detector->ip_buffer);
    opencl_release_buffer(&detector->packet_count_buffer);
    opencl_release_buffer(&detector->entropy_buffer);
    opencl_release_buffer(&detector->threshold_buffer);
    opencl_release_buffer(&detector->detection_buffer);
    
    // Free CPU arrays
    if (detector->unique_ips) free(detector->unique_ips);
    if (detector->packet_counts) free(detector->packet_counts);
    if (detector->entropy_values) free(detector->entropy_values);
    if (detector->detection_results) free(detector->detection_results);
    if (detector->ip_stats) free_ip_statistics(detector->ip_stats);
    
    memset(detector, 0, sizeof(entropy_detector_t));
}

int entropy_detector_process_flows(entropy_detector_t *detector, 
                                  flow_collection_t *flows) {
    if (!detector || !flows) return -1;
    
    uint64_t start_time = metrics_get_current_time_us();
    
    // Create time windows
    time_window_t *windows;
    size_t window_count;
    
    if (create_time_windows(flows, &windows, &window_count, 
                           detector->config.window_size_ms) != 0) {
        fprintf(stderr, "Failed to create time windows\n");
        return -1;
    }
    
    printf("Processing %zu flows in %zu time windows\n", flows->count, window_count);
    
    // Process each window
    for (size_t i = 0; i < window_count; i++) {
        if (windows[i].flow_count > 0) {
            if (entropy_detector_process_window(detector, &windows[i]) != 0) {
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

int entropy_detector_process_window(entropy_detector_t *detector, 
                                   time_window_t *window) {
    if (!detector || !window) return -1;
    
    // Record start time for performance metrics
    uint64_t start_time = metrics_get_current_time_us();
    
    // Build IP statistics for this window
    if (entropy_detector_build_ip_statistics(detector, window) != 0) {
        fprintf(stderr, "Failed to build IP statistics\n");
        return -1;
    }
    
    if (detector->ip_stats_count == 0) {
        return 0; // No data to process
    }
    
    // Calculate total packets and bytes for metrics
    uint64_t total_packets = 0;
    uint64_t total_bytes = 0;
    for (size_t i = 0; i < window->flow_count; i++) {
        total_packets += window->flows[i].total_fwd_packets + window->flows[i].total_bwd_packets;
        total_bytes += window->flows[i].total_fwd_bytes + window->flows[i].total_bwd_bytes;
    }
    
    // Calculate entropy using GPU
    uint64_t gpu_start_time = metrics_get_current_time_us();
    if (entropy_detector_calculate_entropy_gpu(detector, detector->ip_stats, 
                                              detector->ip_stats_count) != 0) {
        fprintf(stderr, "GPU entropy calculation failed, falling back to CPU\n");
        
        // CPU fallback
        float entropy = entropy_detector_calculate_entropy_cpu(detector->ip_stats, 
                                                             detector->ip_stats_count);
        detector->entropy_values[0] = entropy;
        
        // Detect attacks
        if (entropy_detector_detect_attacks_cpu(detector, detector->entropy_values, 1) != 0) {
            fprintf(stderr, "CPU attack detection failed\n");
            return -1;
        }
        
        // Record CPU processing time (no GPU time)
        if (detector->metrics) {
            uint64_t processing_time = metrics_get_current_time_us() - start_time;
            metrics_record_processing_time(detector->metrics, processing_time);
        }
    } else {
        // GPU detection
        if (entropy_detector_detect_attacks_gpu(detector, detector->entropy_values, 
                                              detector->ip_stats_count) != 0) {
            fprintf(stderr, "GPU attack detection failed\n");
            return -1;
        }
        
        // Record GPU processing time
        if (detector->metrics) {
            uint64_t gpu_time = metrics_get_current_time_us() - gpu_start_time;
            uint64_t total_time = metrics_get_current_time_us() - start_time;
            metrics_record_gpu_time(detector->metrics, gpu_time, 0); // No memory transfer time
            metrics_record_processing_time(detector->metrics, total_time);
        }
    }
    
    // Record performance metrics
    if (detector->metrics) {
        detector->metrics->performance.total_packets_processed += total_packets;
        detector->metrics->performance.total_bytes_processed += total_bytes;
        detector->metrics->performance.total_flows_processed += window->flow_count;
    }
    
    // Analyze results
    if (entropy_detector_analyze_results(detector, window, detector->detection_results) != 0) {
        fprintf(stderr, "Failed to analyze detection results\n");
        return -1;
    }
    
    return 0;
}

int entropy_detector_build_ip_statistics(entropy_detector_t *detector, 
                                        time_window_t *window) {
    // Simple hash table for IP statistics
    #define HASH_SIZE 65536
    ip_stats_t *hash_table[HASH_SIZE];
    memset(hash_table, 0, sizeof(hash_table));
    
    detector->ip_stats_count = 0;
    
    // Count packets per IP
    for (size_t i = 0; i < window->flow_count; i++) {
        uint32_t src_ip = window->flows[i].src_ip;
        uint32_t dst_ip = window->flows[i].dst_ip;
        uint32_t src_packets = window->flows[i].total_fwd_packets;
        uint32_t dst_packets = window->flows[i].total_bwd_packets;
        
        // Process source IP
        uint32_t hash = src_ip % HASH_SIZE;
        ip_stats_t *current = hash_table[hash];
        while (current && current->ip != src_ip) {
            current = current->next;
        }
        if (!current) {
            current = (ip_stats_t*)malloc(sizeof(ip_stats_t));
            current->ip = src_ip;
            current->packet_count = 0;
            current->byte_count = 0;
            current->first_seen = window->flows[i].timestamp;
            current->last_seen = window->flows[i].timestamp;
            current->next = hash_table[hash];
            hash_table[hash] = current;
            detector->ip_stats_count++;
        }
        current->packet_count += src_packets;
        current->byte_count += window->flows[i].total_fwd_bytes;
        
        // Process destination IP
        hash = dst_ip % HASH_SIZE;
        current = hash_table[hash];
        while (current && current->ip != dst_ip) {
            current = current->next;
        }
        if (!current) {
            current = (ip_stats_t*)malloc(sizeof(ip_stats_t));
            current->ip = dst_ip;
            current->packet_count = 0;
            current->byte_count = 0;
            current->first_seen = window->flows[i].timestamp;
            current->last_seen = window->flows[i].timestamp;
            current->next = hash_table[hash];
            hash_table[hash] = current;
            detector->ip_stats_count++;
        }
        current->packet_count += dst_packets;
        current->byte_count += window->flows[i].total_bwd_bytes;
    }
    
    // Convert to array
    if (detector->ip_stats) {
        free_ip_statistics(detector->ip_stats);
    }
    
    detector->ip_stats = (ip_stats_t*)malloc(detector->ip_stats_count * sizeof(ip_stats_t));
    if (!detector->ip_stats) {
        fprintf(stderr, "Failed to allocate IP statistics array\n");
        return -1;
    }
    
    size_t idx = 0;
    for (int i = 0; i < HASH_SIZE; i++) {
        ip_stats_t *current = hash_table[i];
        while (current) {
            detector->ip_stats[idx++] = *current;
            ip_stats_t *next = current->next;
            free(current);
            current = next;
        }
    }
    
    return 0;
}

int entropy_detector_calculate_entropy_gpu(entropy_detector_t *detector, 
                                          ip_stats_t *ip_stats, size_t count) {
    if (!detector->opencl_ctx || count == 0) return -1;
    
    // Prepare data for GPU
    for (size_t i = 0; i < count; i++) {
        detector->unique_ips[i] = ip_stats[i].ip;
        detector->packet_counts[i] = ip_stats[i].packet_count;
    }
    
    // Copy data to GPU
    if (opencl_write_buffer(detector->opencl_ctx, &detector->ip_buffer, 
                           detector->unique_ips, count * sizeof(uint32_t)) != 0) {
        return -1;
    }
    
    if (opencl_write_buffer(detector->opencl_ctx, &detector->packet_count_buffer, 
                           detector->packet_counts, count * sizeof(uint32_t)) != 0) {
        return -1;
    }
    
    // Execute entropy calculation kernel
    if (opencl_execute_entropy_kernel(detector->opencl_ctx, 
                                     &detector->ip_buffer,
                                     &detector->packet_count_buffer,
                                     &detector->entropy_buffer,
                                     count, count) != 0) {
        return -1;
    }
    
    // Read results back
    if (opencl_read_buffer(detector->opencl_ctx, &detector->entropy_buffer, 
                          detector->entropy_values, count * sizeof(float)) != 0) {
        return -1;
    }
    
    return 0;
}

int entropy_detector_detect_attacks_gpu(entropy_detector_t *detector, 
                                        float *entropy_values, size_t count) {
    if (!detector->opencl_ctx || count == 0) return -1;
    
    // Calculate threshold if using dynamic threshold
    if (detector->config.use_dynamic_threshold) {
        detector->current_threshold = entropy_detector_calculate_threshold(detector, 
                                                                          entropy_values, count);
    }
    
    // Copy threshold to GPU
    if (opencl_write_buffer(detector->opencl_ctx, &detector->threshold_buffer, 
                           &detector->current_threshold, sizeof(float)) != 0) {
        return -1;
    }
    
    // Execute detection kernel
    // Note: This would require a separate kernel for detection
    // For now, we'll do detection on CPU
    return entropy_detector_detect_attacks_cpu(detector, entropy_values, count);
}

float entropy_detector_calculate_entropy_cpu(ip_stats_t *ip_stats, size_t count) {
    if (count == 0) return 0.0f;
    
    // Calculate total packets
    uint32_t total_packets = 0;
    for (size_t i = 0; i < count; i++) {
        total_packets += ip_stats[i].packet_count;
    }
    
    if (total_packets == 0) return 0.0f;
    
    // Calculate Shannon entropy
    float entropy = 0.0f;
    for (size_t i = 0; i < count; i++) {
        if (ip_stats[i].packet_count > 0) {
            float probability = (float)ip_stats[i].packet_count / (float)total_packets;
            entropy -= probability * log2f(probability);
        }
    }
    
    return entropy;
}

int entropy_detector_detect_attacks_cpu(entropy_detector_t *detector, 
                                        float *entropy_values, size_t count) {
    for (size_t i = 0; i < count; i++) {
        if (entropy_values[i] < detector->current_threshold) {
            detector->detection_results[i] = 1; // Attack detected
        } else {
            detector->detection_results[i] = 0; // Normal traffic
        }
    }
    
    return 0;
}

float entropy_detector_calculate_threshold(entropy_detector_t *detector, 
                                          float *entropy_values, size_t count) {
    if (count == 0) return detector->config.entropy_threshold;
    
    // Calculate mean
    float sum = 0.0f;
    for (size_t i = 0; i < count; i++) {
        sum += entropy_values[i];
    }
    float mean = sum / (float)count;
    
    // Calculate standard deviation
    float variance = 0.0f;
    for (size_t i = 0; i < count; i++) {
        float diff = entropy_values[i] - mean;
        variance += diff * diff;
    }
    float std_dev = sqrtf(variance / (float)count);
    
    // Dynamic threshold based on sensitivity
    float threshold = mean - (detector->config.sensitivity * std_dev);
    
    // Ensure threshold is reasonable
    if (threshold < 0.0f) threshold = 0.0f;
    if (threshold > 10.0f) threshold = 10.0f;
    
    return threshold;
}

int entropy_detector_analyze_results(entropy_detector_t *detector, 
                                    time_window_t *window, 
                                    uint32_t *detection_results) {
    if (!detector || !window || !detection_results) return -1;
    
    // Count detections
    uint32_t attack_detections = 0;
    uint32_t total_detections = 0;
    
    for (size_t i = 0; i < detector->ip_stats_count; i++) {
        if (detection_results[i] == 1) {
            attack_detections++;
        }
        total_detections++;
    }
    
    // Update metrics - record detection results for each flow
    if (detector->metrics) {
        // Determine if window contains attacks (any IP flagged as attack)
        int window_has_attack = (attack_detections > 0) ? 1 : 0;
        
        // For each flow, record the detection result and blocking metrics
        for (size_t i = 0; i < window->flow_count; i++) {
            int is_attack = is_attack_flow(&window->flows[i]);
            int detected_as_attack = window_has_attack;  // If any IP flagged, all flows in window flagged
            
            metrics_record_detection(detector->metrics, is_attack, detected_as_attack);
            
            // Record blocking metrics (simulate blocking when attack detected)
            uint32_t flow_packets = window->flows[i].total_fwd_packets + window->flows[i].total_bwd_packets;
            uint32_t flow_bytes = window->flows[i].total_fwd_bytes + window->flows[i].total_bwd_bytes;
            int was_blocked = (detected_as_attack && window_has_attack) ? 1 : 0; // Block if detected as attack
            
            metrics_record_blocking(detector->metrics, is_attack, was_blocked, flow_packets, flow_bytes);
        }
    }
    
    // Print results
    if (attack_detections > 0) {
        printf("Entropy Detection: ATTACK detected in window (%.2f%% of IPs flagged)\n", 
               (float)attack_detections / total_detections * 100.0f);
    }
    
    return 0;
}

void entropy_detector_print_statistics(entropy_detector_t *detector) {
    printf("\n=== Entropy Detector Statistics ===\n");
    printf("Configuration:\n");
    printf("  Sensitivity: %.2f\n", detector->config.sensitivity);
    printf("  Window Size: %llu ms\n", detector->config.window_size_ms);
    printf("  Min Packets: %u\n", detector->config.min_packets);
    printf("  Use Dynamic Threshold: %s\n", detector->config.use_dynamic_threshold ? "Yes" : "No");
    printf("  Current Threshold: %.4f\n", detector->current_threshold);
    printf("  Baseline Entropy: %.4f\n", detector->baseline_entropy);
    printf("  IP Stats Count: %zu\n", detector->ip_stats_count);
}

void entropy_detector_set_config(entropy_detector_t *detector, 
                                const entropy_config_t *config) {
    if (detector && config) {
        detector->config = *config;
    }
}
