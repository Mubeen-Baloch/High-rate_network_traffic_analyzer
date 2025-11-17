#include "svm_detector.h"
#include "metrics.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

// Include the generated SVM model
#include "svm_model.h"

void svm_detector_get_default_config(svm_config_t *config) {
    config->gamma = SVM_GAMMA;
    config->c_parameter = 1.0f;
    config->max_iterations = 1000;
    config->convergence_threshold = 0.001f;
    config->use_gpu = 1; // Use GPU by default
}

int svm_detector_init(svm_detector_t *detector, opencl_context_t *opencl_ctx, 
                     const svm_config_t *config, algorithm_metrics_t *metrics) {
    memset(detector, 0, sizeof(svm_detector_t));
    
    detector->opencl_ctx = opencl_ctx;
    detector->metrics = metrics;
    
    if (config) {
        detector->config = *config;
    } else {
        svm_detector_get_default_config(&detector->config);
    }
    
    // Initialize SVM model
    if (svm_model_init(&detector->model, SVM_NUM_FEATURES) != 0) {
        fprintf(stderr, "Failed to initialize SVM model\n");
        return -1;
    }
    
    // Set model parameters from generated header
    detector->model.num_support_vectors = SVM_NUM_SUPPORT_VECTORS;
    detector->model.num_features = SVM_NUM_FEATURES;
    detector->model.gamma = SVM_GAMMA;
    detector->model.bias = SVM_BIAS;
    detector->model.trained = 1;
    
    // Allocate model arrays
    if (svm_model_allocate(&detector->model, SVM_NUM_SUPPORT_VECTORS) != 0) {
        fprintf(stderr, "Failed to allocate SVM model arrays\n");
        svm_detector_cleanup(detector);
        return -1;
    }
    
    // Copy model data from generated arrays
    memcpy(detector->model.weights, svm_weights, SVM_NUM_SUPPORT_VECTORS * sizeof(float));
    memcpy(detector->model.support_vectors, svm_support_vectors, 
           SVM_NUM_SUPPORT_VECTORS * SVM_NUM_FEATURES * sizeof(float));
    memcpy(detector->model.feature_means, svm_feature_means, SVM_NUM_FEATURES * sizeof(float));
    memcpy(detector->model.feature_stds, svm_feature_stds, SVM_NUM_FEATURES * sizeof(float));
    
    // Initialize GPU buffers if using GPU
    if (detector->config.use_gpu && detector->opencl_ctx) {
        size_t max_samples = 10000; // Maximum samples per batch
        
        if (opencl_create_buffer(detector->opencl_ctx, &detector->feature_buffer, 
                               max_samples * SVM_NUM_FEATURES * sizeof(float), 
                               CL_MEM_READ_WRITE) != 0) {
            fprintf(stderr, "Failed to create feature buffer\n");
            svm_detector_cleanup(detector);
            return -1;
        }
        
        if (opencl_create_buffer(detector->opencl_ctx, &detector->weight_buffer, 
                               SVM_NUM_SUPPORT_VECTORS * sizeof(float), 
                               CL_MEM_READ_ONLY) != 0) {
            fprintf(stderr, "Failed to create weight buffer\n");
            svm_detector_cleanup(detector);
            return -1;
        }
        
        if (opencl_create_buffer(detector->opencl_ctx, &detector->support_vector_buffer, 
                               SVM_NUM_SUPPORT_VECTORS * SVM_NUM_FEATURES * sizeof(float), 
                               CL_MEM_READ_ONLY) != 0) {
            fprintf(stderr, "Failed to create support vector buffer\n");
            svm_detector_cleanup(detector);
            return -1;
        }
        
        if (opencl_create_buffer(detector->opencl_ctx, &detector->bias_buffer, 
                               sizeof(float), CL_MEM_READ_ONLY) != 0) {
            fprintf(stderr, "Failed to create bias buffer\n");
            svm_detector_cleanup(detector);
            return -1;
        }
        
        if (opencl_create_buffer(detector->opencl_ctx, &detector->prediction_buffer, 
                               max_samples * sizeof(float), CL_MEM_WRITE_ONLY) != 0) {
            fprintf(stderr, "Failed to create prediction buffer\n");
            svm_detector_cleanup(detector);
            return -1;
        }
        
        // Copy model data to GPU
        opencl_write_buffer(detector->opencl_ctx, &detector->weight_buffer, 
                           detector->model.weights, SVM_NUM_SUPPORT_VECTORS * sizeof(float));
        opencl_write_buffer(detector->opencl_ctx, &detector->support_vector_buffer, 
                           detector->model.support_vectors, 
                           SVM_NUM_SUPPORT_VECTORS * SVM_NUM_FEATURES * sizeof(float));
        opencl_write_buffer(detector->opencl_ctx, &detector->bias_buffer, 
                           &detector->model.bias, sizeof(float));
    }
    
    // Initialize CPU arrays
    detector->max_samples = 10000;
    detector->features = (float*)malloc(detector->max_samples * SVM_NUM_FEATURES * sizeof(float));
    detector->predictions = (float*)malloc(detector->max_samples * sizeof(float));
    detector->normalized_features = (float*)malloc(detector->max_samples * SVM_NUM_FEATURES * sizeof(float));
    
    if (!detector->features || !detector->predictions || !detector->normalized_features) {
        fprintf(stderr, "Failed to allocate CPU arrays\n");
        svm_detector_cleanup(detector);
        return -1;
    }
    
    detector->num_features = SVM_NUM_FEATURES;
    
    printf("SVM detector initialized successfully\n");
    printf("  Features: %u\n", detector->num_features);
    printf("  Support Vectors: %u\n", detector->model.num_support_vectors);
    printf("  Gamma: %.6f\n", detector->model.gamma);
    printf("  Bias: %.6f\n", detector->model.bias);
    printf("  Use GPU: %s\n", detector->config.use_gpu ? "Yes" : "No");
    
    return 0;
}

void svm_detector_cleanup(svm_detector_t *detector) {
    // Release GPU buffers
    opencl_release_buffer(&detector->feature_buffer);
    opencl_release_buffer(&detector->weight_buffer);
    opencl_release_buffer(&detector->support_vector_buffer);
    opencl_release_buffer(&detector->bias_buffer);
    opencl_release_buffer(&detector->prediction_buffer);
    
    // Free CPU arrays
    if (detector->features) free(detector->features);
    if (detector->predictions) free(detector->predictions);
    if (detector->normalized_features) free(detector->normalized_features);
    
    // Cleanup model
    svm_model_cleanup(&detector->model);
    
    memset(detector, 0, sizeof(svm_detector_t));
}

int svm_detector_process_flows(svm_detector_t *detector, flow_collection_t *flows) {
    if (!detector || !flows) return -1;
    
    uint64_t start_time = metrics_get_current_time_us();
    
    // Create time windows
    time_window_t *windows;
    size_t window_count;
    
    if (create_time_windows(flows, &windows, &window_count, 1000) != 0) { // 1 second windows
        fprintf(stderr, "Failed to create time windows\n");
        return -1;
    }
    
    printf("Processing %zu flows in %zu time windows with SVM\n", flows->count, window_count);
    
    // Process each window
    for (size_t i = 0; i < window_count; i++) {
        if (windows[i].flow_count > 0) {
            if (svm_detector_process_window(detector, &windows[i]) != 0) {
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

int svm_detector_process_window(svm_detector_t *detector, time_window_t *window) {
    if (!detector || !window) return -1;
    
    printf("Processing %zu flows in 1 time windows with SVM\n", window->flow_count);
    
    // Process flows in batches to handle large datasets
    size_t batch_size = detector->max_samples;
    size_t total_processed = 0;
    size_t total_attacks_detected = 0;
    
    // Accumulate per-flow predictions across all batches
    int *predictions_all = NULL;
    if (window->flow_count > 0) {
        predictions_all = (int*)calloc(window->flow_count, sizeof(int));
        if (!predictions_all) {
            fprintf(stderr, "Failed to allocate predictions buffer\n");
            return -1;
        }
    }
    
    for (size_t batch_start = 0; batch_start < window->flow_count; batch_start += batch_size) {
        size_t current_batch_size = (batch_start + batch_size > window->flow_count) ? 
                                   (window->flow_count - batch_start) : batch_size;
        
        // Extract features for current batch
        if (svm_detector_extract_features_batch(detector, window, batch_start, current_batch_size) != 0) {
            fprintf(stderr, "Failed to extract features for batch %zu\n", batch_start / batch_size);
            continue;
        }
        
        // Normalize features for current batch
        if (svm_detector_normalize_features(detector, detector->features, current_batch_size) != 0) {
            fprintf(stderr, "Failed to normalize features for batch %zu\n", batch_start / batch_size);
            continue;
        }
        
        // Perform SVM inference on current batch
        if (svm_detector_inference(detector, detector->normalized_features, current_batch_size) != 0) {
            fprintf(stderr, "Failed to perform SVM inference for batch %zu\n", batch_start / batch_size);
            continue;
        }
        
        // Count attacks in current batch and copy predictions into per-flow array
        for (size_t i = 0; i < current_batch_size; i++) {
            int is_attack_pred = (detector->predictions[i] > 0) ? 1 : 0;
            predictions_all[batch_start + i] = is_attack_pred;
            if (is_attack_pred) {
                total_attacks_detected++;
            }
        }
        
        total_processed += current_batch_size;
        
        // Progress update for large datasets
        if (window->flow_count > 100000 && (batch_start / batch_size) % 100 == 0) {
            printf("SVM: Processed %zu/%zu flows (%.1f%%)\n", 
                   total_processed, window->flow_count, 
                   (float)total_processed / window->flow_count * 100);
        }
    }
    
    printf("SVM Detection: %zu attacks detected in %zu flows (%.2f%%)\n", 
           total_attacks_detected, total_processed, 
           (float)total_attacks_detected / total_processed * 100);
    
    // Record metrics
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
            // Use accumulated per-flow prediction
            int predicted_as_attack = (i < total_processed) ? predictions_all[i] : 0;
            
            metrics_record_detection(detector->metrics, is_attack, predicted_as_attack);
            
            // Track first attack time and first detection time for lead time calculation
            if (is_attack && detector->metrics->first_attack_time == 0) {
                detector->metrics->first_attack_time = window->flows[i].timestamp;
            }
            if (predicted_as_attack && detector->metrics->first_detection_time == 0) {
                detector->metrics->first_detection_time = metrics_get_current_time_us();
            }
            
            // Record blocking metrics (simulate blocking when attack detected)
            uint32_t flow_packets = window->flows[i].total_fwd_packets + window->flows[i].total_bwd_packets;
            uint32_t flow_bytes = window->flows[i].total_fwd_bytes + window->flows[i].total_bwd_bytes;
            int was_blocked = predicted_as_attack ? 1 : 0; // Block if predicted as attack
            
            metrics_record_blocking(detector->metrics, is_attack, was_blocked, flow_packets, flow_bytes);
        }
    }
    
    if (predictions_all) {
        free(predictions_all);
    }
    
    return 0;
}

int svm_detector_extract_features_batch(svm_detector_t *detector, time_window_t *window, 
                                        size_t batch_start, size_t batch_size) {
    if (!detector || !window) return -1;
    
    // Extract features for each flow in the batch
    for (size_t i = 0; i < batch_size; i++) {
        size_t flow_idx = batch_start + i;
        if (flow_idx >= window->flow_count) break;
        
        network_flow_t *flow = &window->flows[flow_idx];
        float *features = &detector->features[i * detector->num_features];
        
        // Feature 0: Flow duration (normalized)
        features[0] = (float)flow->flow_duration / 1000000.0f; // Convert to seconds
        
        // Feature 1: Total forward packets
        features[1] = (float)flow->total_fwd_packets;
        
        // Feature 2: Total backward packets
        features[2] = (float)flow->total_bwd_packets;
        
        // Feature 3: Total forward bytes
        features[3] = (float)flow->total_fwd_bytes;
        
        // Feature 4: Total backward bytes
        features[4] = (float)flow->total_bwd_bytes;
        
        // Feature 5: Flow bytes per second
        features[5] = (float)flow->flow_bytes_per_sec;
        
        // Feature 6: Flow packets per second
        features[6] = (float)flow->flow_packets_per_sec;
        
        // Feature 7: Forward packet length mean
        features[7] = (float)flow->fwd_packet_length_mean;
        
        // Feature 8: Forward packet length std
        features[8] = (float)flow->fwd_packet_length_std;
        
        // Feature 9: Backward packet length mean
        features[9] = (float)flow->bwd_packet_length_mean;
        
        // Feature 10: Backward packet length std
        features[10] = (float)flow->bwd_packet_length_std;
        
        // Feature 11: Flow IAT mean
        features[11] = (float)flow->flow_iat_mean;
        
        // Feature 12: Flow IAT std
        features[12] = (float)flow->flow_iat_std;
        
        // Feature 13: Forward IAT mean
        features[13] = (float)flow->fwd_iat_mean;
        
        // Feature 14: Backward IAT mean
        features[14] = (float)flow->bwd_iat_mean;
        
        // Feature 15: Protocol
        features[15] = (float)flow->protocol;
        
        // Feature 16: Source port
        features[16] = (float)flow->src_port;
        
        // Feature 17: Destination port
        features[17] = (float)flow->dst_port;
        
        // Feature 18: Forward PSH flags
        features[18] = (float)flow->fwd_psh_flags;
        
        // Feature 19: Backward PSH flags
        features[19] = (float)flow->bwd_psh_flags;
        
        // Feature 20: Forward URG flags
        features[20] = (float)flow->fwd_urg_flags;
        
        // Feature 21: Backward URG flags
        features[21] = (float)flow->bwd_urg_flags;
        
        // Feature 22: Forward header length
        features[22] = (float)flow->fwd_header_length;
        
        // Feature 23: Initial window bytes forward
        features[23] = (float)flow->init_win_bytes_forward;
    }
    
    return 0;
}

int svm_detector_extract_features(svm_detector_t *detector, time_window_t *window) {
    if (detector->config.use_gpu && detector->opencl_ctx) {
        return svm_detector_extract_features_gpu(detector, window);
    } else {
        return svm_detector_extract_features_cpu(detector, window);
    }
}

int svm_detector_extract_features_cpu(svm_detector_t *detector, time_window_t *window) {
    if (!detector || !window) return -1;
    
    // Extract features for each flow
    for (size_t i = 0; i < window->flow_count && i < detector->max_samples; i++) {
        network_flow_t *flow = &window->flows[i];
        float *features = &detector->features[i * detector->num_features];
        
        // Feature 0: Flow duration (normalized)
        features[0] = (float)flow->flow_duration / 1000000.0f; // Convert to seconds
        
        // Feature 1: Total forward packets
        features[1] = (float)flow->total_fwd_packets;
        
        // Feature 2: Total backward packets
        features[2] = (float)flow->total_bwd_packets;
        
        // Feature 3: Total forward bytes
        features[3] = (float)flow->total_fwd_bytes;
        
        // Feature 4: Total backward bytes
        features[4] = (float)flow->total_bwd_bytes;
        
        // Feature 5: Flow bytes per second
        features[5] = (float)flow->flow_bytes_per_sec;
        
        // Feature 6: Flow packets per second
        features[6] = (float)flow->flow_packets_per_sec;
        
        // Feature 7: Forward packet length mean
        features[7] = (float)flow->fwd_packet_length_mean;
        
        // Feature 8: Forward packet length std
        features[8] = (float)flow->fwd_packet_length_std;
        
        // Feature 9: Backward packet length mean
        features[9] = (float)flow->bwd_packet_length_mean;
        
        // Feature 10: Backward packet length std
        features[10] = (float)flow->bwd_packet_length_std;
        
        // Feature 11: Flow IAT mean
        features[11] = (float)flow->flow_iat_mean;
        
        // Feature 12: Flow IAT std
        features[12] = (float)flow->flow_iat_std;
        
        // Feature 13: Flow IAT max
        features[13] = (float)flow->flow_iat_max;
        
        // Feature 14: Flow IAT min
        features[14] = (float)flow->flow_iat_min;
        
        // Feature 15: Protocol
        features[15] = (float)flow->protocol;
        
        // Feature 16: Source port (normalized)
        features[16] = (float)flow->src_port / 65535.0f;
        
        // Feature 17: Destination port (normalized)
        features[17] = (float)flow->dst_port / 65535.0f;
        
        // Feature 18: Forward PSH flags
        features[18] = (float)flow->fwd_psh_flags;
        
        // Feature 19: Backward PSH flags
        features[19] = (float)flow->bwd_psh_flags;
        
        // Feature 20: Forward URG flags
        features[20] = (float)flow->fwd_urg_flags;
        
        // Feature 21: Backward URG flags
        features[21] = (float)flow->bwd_urg_flags;
        
        // Feature 22: Initial window bytes forward
        features[22] = (float)flow->init_win_bytes_forward;
        
        // Feature 23: Initial window bytes backward
        features[23] = (float)flow->init_win_bytes_backward;
    }
    
    return 0;
}

int svm_detector_extract_features_gpu(svm_detector_t *detector, time_window_t *window) {
    // For now, fall back to CPU extraction
    // GPU feature extraction would require packing flow data and calling GPU kernel
    return svm_detector_extract_features_cpu(detector, window);
}

int svm_detector_inference(svm_detector_t *detector, float *features, uint32_t num_samples) {
    if (detector->config.use_gpu && detector->opencl_ctx) {
        return svm_detector_inference_gpu(detector, features, num_samples);
    } else {
        return svm_detector_inference_cpu(detector, features, num_samples);
    }
}

int svm_detector_inference_cpu(svm_detector_t *detector, float *features, uint32_t num_samples) {
    if (!detector || !features) return -1;
    
    // Normalize features
    if (svm_detector_normalize_features(detector, features, num_samples) != 0) {
        return -1;
    }
    
    // Perform SVM inference for each sample
    for (uint32_t i = 0; i < num_samples; i++) {
        float *sample_features = &detector->normalized_features[i * detector->num_features];
        float prediction = 0.0f;
        
        // Calculate SVM decision function
        for (uint32_t j = 0; j < detector->model.num_support_vectors; j++) {
            float kernel_value = 0.0f;
            
            // Calculate RBF kernel: K(x, x') = exp(-gamma * ||x - x'||^2)
            for (uint32_t k = 0; k < detector->num_features; k++) {
                float diff = sample_features[k] - detector->model.support_vectors[j * detector->num_features + k];
                kernel_value += diff * diff;
            }
            
            kernel_value = expf(-detector->model.gamma * kernel_value);
            
            // Add weighted kernel value
            prediction += detector->model.weights[j] * kernel_value;
        }
        
        // Add bias
        prediction += detector->model.bias;
        
        // Apply sign function for binary classification
        detector->predictions[i] = (prediction > 0.0f) ? 1.0f : 0.0f;
    }
    
    return 0;
}

int svm_detector_inference_gpu(svm_detector_t *detector, float *features, uint32_t num_samples) {
    if (!detector->opencl_ctx) return -1;
    
    uint64_t gpu_start_us = metrics_get_current_time_us();
    
    // Copy features to GPU
    if (opencl_write_buffer(detector->opencl_ctx, &detector->feature_buffer, 
                           features, num_samples * detector->num_features * sizeof(float)) != 0) {
        return -1;
    }
    
    // Execute SVM inference kernel
    if (opencl_execute_svm_kernel(detector->opencl_ctx, 
                                 &detector->feature_buffer,
                                 &detector->weight_buffer,
                                 &detector->support_vector_buffer,
                                 &detector->bias_buffer,
                                 &detector->prediction_buffer,
                                 num_samples, detector->num_features, 
                                 detector->model.num_support_vectors, 
                                 detector->model.gamma) != 0) {
        return -1;
    }
    
    // Read predictions back
    if (opencl_read_buffer(detector->opencl_ctx, &detector->prediction_buffer, 
                          detector->predictions, num_samples * sizeof(float)) != 0) {
        return -1;
    }
    
    uint64_t gpu_end_us = metrics_get_current_time_us();
    if (detector->metrics) {
        uint64_t gpu_time_us = (gpu_end_us > gpu_start_us) ? (gpu_end_us - gpu_start_us) : 0;
        metrics_record_gpu_time(detector->metrics, gpu_time_us, 0);
    }
    
    return 0;
}

int svm_detector_normalize_features(svm_detector_t *detector, float *features, uint32_t num_samples) {
    if (!detector || !features) return -1;
    
    // Normalize each feature
    for (uint32_t i = 0; i < num_samples; i++) {
        float *sample_features = &features[i * detector->num_features];
        float *normalized_features = &detector->normalized_features[i * detector->num_features];
        
        for (uint32_t j = 0; j < detector->num_features; j++) {
            // Normalize: (x - mean) / std
            normalized_features[j] = (sample_features[j] - detector->model.feature_means[j]) / 
                                    detector->model.feature_stds[j];
        }
    }
    
    return 0;
}

int svm_detector_analyze_results(svm_detector_t *detector, time_window_t *window, 
                                float *predictions) {
    if (!detector || !window || !predictions) return -1;
    
    // Count predictions
    uint32_t attack_predictions = 0;
    uint32_t total_predictions = 0;
    
    for (size_t i = 0; i < window->flow_count; i++) {
        if (predictions[i] > 0.5f) {
            attack_predictions++;
        }
        total_predictions++;
    }
    
    // Update metrics
    if (detector->metrics) {
        for (size_t i = 0; i < window->flow_count; i++) {
            int is_attack = is_attack_flow(&window->flows[i]);
            int predicted_as_attack = (predictions[i] > 0.5f) ? 1 : 0;
            
            metrics_record_detection(detector->metrics, is_attack, predicted_as_attack);
        }
    }
    
    // Print results
    if (attack_predictions > 0) {
        printf("SVM Detection: ATTACK predicted in window (%.2f%% of flows flagged)\n", 
               (float)attack_predictions / total_predictions * 100.0f);
    }
    
    return 0;
}

void svm_detector_print_statistics(svm_detector_t *detector) {
    printf("\n=== SVM Detector Statistics ===\n");
    printf("Configuration:\n");
    printf("  Gamma: %.6f\n", detector->config.gamma);
    printf("  C Parameter: %.2f\n", detector->config.c_parameter);
    printf("  Max Iterations: %u\n", detector->config.max_iterations);
    printf("  Use GPU: %s\n", detector->config.use_gpu ? "Yes" : "No");
    
    printf("Model:\n");
    printf("  Trained: %s\n", detector->model.trained ? "Yes" : "No");
    printf("  Features: %u\n", detector->model.num_features);
    printf("  Support Vectors: %u\n", detector->model.num_support_vectors);
    printf("  Gamma: %.6f\n", detector->model.gamma);
    printf("  Bias: %.6f\n", detector->model.bias);
}

int svm_model_init(svm_model_t *model, uint32_t num_features) {
    memset(model, 0, sizeof(svm_model_t));
    model->num_features = num_features;
    return 0;
}

void svm_model_cleanup(svm_model_t *model) {
    if (model->weights) free(model->weights);
    if (model->support_vectors) free(model->support_vectors);
    if (model->feature_means) free(model->feature_means);
    if (model->feature_stds) free(model->feature_stds);
    
    memset(model, 0, sizeof(svm_model_t));
}

int svm_model_allocate(svm_model_t *model, uint32_t num_support_vectors) {
    model->weights = (float*)malloc(num_support_vectors * sizeof(float));
    model->support_vectors = (float*)malloc(num_support_vectors * model->num_features * sizeof(float));
    model->feature_means = (float*)malloc(model->num_features * sizeof(float));
    model->feature_stds = (float*)malloc(model->num_features * sizeof(float));
    
    if (!model->weights || !model->support_vectors || 
        !model->feature_means || !model->feature_stds) {
        svm_model_cleanup(model);
        return -1;
    }
    
    return 0;
}

void svm_detector_set_config(svm_detector_t *detector, const svm_config_t *config) {
    if (detector && config) {
        detector->config = *config;
    }
}
