#include "metrics.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/time.h>
#endif

void metrics_init(system_metrics_t *metrics) {
    memset(metrics, 0, sizeof(system_metrics_t));
    metrics->experiment_start_time = metrics_get_current_time_us();
}

void metrics_start_experiment(system_metrics_t *metrics, const char *dataset_name, 
                           const char *config) {
    metrics->experiment_start_time = metrics_get_current_time_us();
    strncpy(metrics->dataset_name, dataset_name, sizeof(metrics->dataset_name) - 1);
    strncpy(metrics->experiment_config, config, sizeof(metrics->experiment_config) - 1);
    metrics->total_experiments++;
}

void metrics_end_experiment(system_metrics_t *metrics) {
    metrics->experiment_end_time = metrics_get_current_time_us();
}

void metrics_start_algorithm(algorithm_metrics_t *metrics, const char *algorithm_name) {
    memset(metrics, 0, sizeof(algorithm_metrics_t));
    strncpy(metrics->algorithm_name, algorithm_name, sizeof(metrics->algorithm_name) - 1);
    metrics->start_time = metrics_get_current_time_us();
}

void metrics_end_algorithm(algorithm_metrics_t *metrics) {
    metrics->end_time = metrics_get_current_time_us();
    
    // Calculate experiment duration (wall-clock time)
    uint64_t experiment_duration_us = (metrics->end_time > metrics->start_time) ? 
                                      (metrics->end_time - metrics->start_time) : 0;
    
    // Calculate detection lead time (time from first attack to first detection)
    if (metrics->first_attack_time > 0 && metrics->first_detection_time > 0) {
        // Convert first_attack_time (flow timestamp) to microseconds relative to experiment start
        // For simplicity, use first_detection_time - first_attack_time if both are in same timebase
        // Otherwise, use first_detection_time - start_time as approximation
        if (metrics->first_detection_time > metrics->start_time) {
            metrics->performance.detection_latency_us = metrics->first_detection_time - metrics->start_time;
        } else {
            metrics->performance.detection_latency_us = 0;
        }
    } else {
        metrics->performance.detection_latency_us = 0;
    }
    
    // Calculate all metrics
    metrics_calculate_detection_metrics(&metrics->detection);
    metrics_calculate_performance_metrics(&metrics->performance, experiment_duration_us);
    metrics_calculate_gpu_metrics(&metrics->gpu, experiment_duration_us);
    metrics_calculate_blocking_metrics(&metrics->blocking);
}

void metrics_record_detection(algorithm_metrics_t *metrics, int is_attack, 
                            int detected_as_attack) {
    if (is_attack && detected_as_attack) {
        metrics->detection.true_positives++;
    } else if (!is_attack && detected_as_attack) {
        metrics->detection.false_positives++;
        metrics->false_alarms++;
    } else if (!is_attack && !detected_as_attack) {
        metrics->detection.true_negatives++;
    } else if (is_attack && !detected_as_attack) {
        metrics->detection.false_negatives++;
    }
    
    if (detected_as_attack) {
        metrics->alerts_generated++;
    }
}

void metrics_record_processing_time(algorithm_metrics_t *metrics, uint64_t processing_time_us) {
    metrics->performance.total_processing_time_us += processing_time_us;
    metrics_add_processing_time(&metrics->performance, processing_time_us);
}

void metrics_record_gpu_time(algorithm_metrics_t *metrics, uint64_t kernel_time_us, 
                           uint64_t transfer_time_us) {
    metrics->gpu.kernel_execution_time_us += kernel_time_us;
    metrics->gpu.memory_transfer_time_us += transfer_time_us;
    metrics->gpu.total_gpu_time_us += kernel_time_us + transfer_time_us;
    metrics->gpu.kernel_calls++;
    metrics->gpu.memory_transfers++;
}

void metrics_record_blocking(algorithm_metrics_t *metrics, int is_attack, 
                          int was_blocked, uint32_t packet_count, uint32_t byte_count) {
    if (is_attack) {
        metrics->blocking.total_attack_packets += packet_count;
        metrics->blocking.total_attack_bytes += byte_count;
        if (was_blocked) {
            metrics->blocking.attack_packets_blocked += packet_count;
            metrics->blocking.attack_bytes_blocked += byte_count;
        }
    } else {
        metrics->blocking.total_benign_packets += packet_count;
        metrics->blocking.total_benign_bytes += byte_count;
        if (was_blocked) {
            metrics->blocking.benign_packets_blocked += packet_count;
            metrics->blocking.benign_bytes_blocked += byte_count;
        }
    }
}

void metrics_calculate_detection_metrics(detection_metrics_t *metrics) {
    uint32_t tp = metrics->true_positives;
    uint32_t fp = metrics->false_positives;
    uint32_t tn = metrics->true_negatives;
    uint32_t fn = metrics->false_negatives;
    
    // Precision: TP / (TP + FP)
    if (tp + fp > 0) {
        metrics->precision = (double)tp / (tp + fp);
    } else {
        metrics->precision = 0.0;
    }
    
    // Recall: TP / (TP + FN)
    if (tp + fn > 0) {
        metrics->recall = (double)tp / (tp + fn);
    } else {
        metrics->recall = 0.0;
    }
    
    // F1-Score: 2 * (precision * recall) / (precision + recall)
    if (metrics->precision + metrics->recall > 0) {
        metrics->f1_score = 2.0 * (metrics->precision * metrics->recall) / 
                           (metrics->precision + metrics->recall);
    } else {
        metrics->f1_score = 0.0;
    }
    
    // Accuracy: (TP + TN) / (TP + TN + FP + FN)
    uint32_t total = tp + tn + fp + fn;
    if (total > 0) {
        metrics->accuracy = (double)(tp + tn) / total;
    } else {
        metrics->accuracy = 0.0;
    }
    
    // False Positive Rate: FP / (FP + TN)
    if (fp + tn > 0) {
        metrics->false_positive_rate = (double)fp / (fp + tn);
    } else {
        metrics->false_positive_rate = 0.0;
    }
}

void metrics_calculate_performance_metrics(performance_metrics_t *metrics, uint64_t experiment_duration_us) {
    if (experiment_duration_us > 0) {
        // Use actual experiment wall-clock time for realistic throughput
        double time_sec = experiment_duration_us / 1000000.0;
        
        // Handle small datasets - mark as N/A if duration too small
        if (time_sec < 0.01) {  // Less than 10ms
            metrics->packets_per_second = 0.0;  // Will display as N/A
            metrics->gbps_throughput = 0.0;
            metrics->bytes_per_second = 0.0;
            metrics->flows_per_second = 0.0;
        } else {
            metrics->packets_per_second = metrics->total_packets_processed / time_sec;
            metrics->bytes_per_second = metrics->total_bytes_processed / time_sec;
            metrics->flows_per_second = metrics->total_flows_processed / time_sec;
            metrics->gbps_throughput = (metrics->bytes_per_second * 8) / (1024.0 * 1024.0 * 1024.0);
        }
        
        // Average processing time per packet (using total processing time, not experiment duration)
        if (metrics->total_packets_processed > 0 && metrics->total_processing_time_us > 0) {
            metrics->avg_processing_time_us = metrics->total_processing_time_us / 
                                            metrics->total_packets_processed;
        }
    }
}

void metrics_calculate_gpu_metrics(gpu_metrics_t *metrics, uint64_t total_experiment_time_us) {
    if (total_experiment_time_us > 0 && metrics->kernel_execution_time_us > 0) {
        // Calculate GPU utilization as: (GPU kernel time / total experiment time) * 100
        metrics->gpu_utilization_percent = 
            ((double)metrics->kernel_execution_time_us / total_experiment_time_us) * 100.0;
        
        // Cap at 100%
        if (metrics->gpu_utilization_percent > 100.0) {
            metrics->gpu_utilization_percent = 100.0;
        }
        
        // Calculate memory utilization (as percentage of experiment time)
        if (metrics->bytes_transferred > 0 && metrics->memory_transfer_time_us > 0) {
            metrics->memory_utilization_percent = 
                ((double)metrics->memory_transfer_time_us / total_experiment_time_us) * 100.0;
            
            // Cap at 100%
            if (metrics->memory_utilization_percent > 100.0) {
                metrics->memory_utilization_percent = 100.0;
            }
        } else {
            metrics->memory_utilization_percent = 0.0;
        }
    } else {
        metrics->gpu_utilization_percent = 0.0;
        metrics->memory_utilization_percent = 0.0;
    }
}

void metrics_calculate_blocking_metrics(blocking_metrics_t *metrics) {
    // Attack blocking rate
    if (metrics->total_attack_packets > 0) {
        metrics->attack_blocking_rate = (double)metrics->attack_packets_blocked / 
                                      metrics->total_attack_packets * 100.0;
    } else {
        metrics->attack_blocking_rate = 0.0;
    }
    
    // Collateral damage rate
    if (metrics->total_benign_packets > 0) {
        metrics->collateral_damage_rate = (double)metrics->benign_packets_blocked / 
                                         metrics->total_benign_packets * 100.0;
    } else {
        metrics->collateral_damage_rate = 0.0;
    }
    
    // Blocking efficiency
    uint32_t total_blocked = metrics->attack_packets_blocked + metrics->benign_packets_blocked;
    if (total_blocked > 0) {
        metrics->blocking_efficiency = (double)metrics->attack_packets_blocked / total_blocked * 100.0;
    } else {
        metrics->blocking_efficiency = 0.0;
    }
}

int metrics_export_csv(system_metrics_t *metrics, const char *filename) {
    FILE *file = fopen(filename, "w");
    if (!file) {
        fprintf(stderr, "Failed to open file for writing: %s\n", filename);
        return -1;
    }
    
    // Write header
    fprintf(file, "Algorithm,Precision,Recall,F1-Score,Accuracy,FPR,Packets/sec,Gbps,GPU_Util%%,Attack_Block%%,Collateral_Damage%%\n");
    
    // Write dataset (ground-truth) traffic metrics row
    fprintf(file, "Dataset,%.4f,%.4f,%.4f,%.4f,%.4f,%.2f,%.4f,%.2f,%.2f,%.2f\n",
            0.0, 0.0, 0.0, 0.0, 0.0,
            metrics->dataset.dataset_packets_per_second,
            metrics->dataset.dataset_gbps,
            0.0, 0.0, 0.0);
    
    // Write entropy metrics
    fprintf(file, "Entropy,%.4f,%.4f,%.4f,%.4f,%.4f,%.2f,%.4f,%.2f,%.2f,%.2f\n",
            metrics->entropy_metrics.detection.precision,
            metrics->entropy_metrics.detection.recall,
            metrics->entropy_metrics.detection.f1_score,
            metrics->entropy_metrics.detection.accuracy,
            metrics->entropy_metrics.detection.false_positive_rate,
            metrics->entropy_metrics.performance.packets_per_second,
            metrics->entropy_metrics.performance.gbps_throughput,
            metrics->entropy_metrics.gpu.gpu_utilization_percent,
            metrics->entropy_metrics.blocking.attack_blocking_rate,
            metrics->entropy_metrics.blocking.collateral_damage_rate);
    
    // Write CUSUM metrics
    fprintf(file, "CUSUM,%.4f,%.4f,%.4f,%.4f,%.4f,%.2f,%.4f,%.2f,%.2f,%.2f\n",
            metrics->cusum_metrics.detection.precision,
            metrics->cusum_metrics.detection.recall,
            metrics->cusum_metrics.detection.f1_score,
            metrics->cusum_metrics.detection.accuracy,
            metrics->cusum_metrics.detection.false_positive_rate,
            metrics->cusum_metrics.performance.packets_per_second,
            metrics->cusum_metrics.performance.gbps_throughput,
            metrics->cusum_metrics.gpu.gpu_utilization_percent,
            metrics->cusum_metrics.blocking.attack_blocking_rate,
            metrics->cusum_metrics.blocking.collateral_damage_rate);
    
    // Write SVM metrics
    fprintf(file, "SVM,%.4f,%.4f,%.4f,%.4f,%.4f,%.2f,%.4f,%.2f,%.2f,%.2f\n",
            metrics->svm_metrics.detection.precision,
            metrics->svm_metrics.detection.recall,
            metrics->svm_metrics.detection.f1_score,
            metrics->svm_metrics.detection.accuracy,
            metrics->svm_metrics.detection.false_positive_rate,
            metrics->svm_metrics.performance.packets_per_second,
            metrics->svm_metrics.performance.gbps_throughput,
            metrics->svm_metrics.gpu.gpu_utilization_percent,
            metrics->svm_metrics.blocking.attack_blocking_rate,
            metrics->svm_metrics.blocking.collateral_damage_rate);
    
    // Write combined metrics
    fprintf(file, "Combined,%.4f,%.4f,%.4f,%.4f,%.4f,%.2f,%.4f,%.2f,%.2f,%.2f\n",
            metrics->combined_metrics.detection.precision,
            metrics->combined_metrics.detection.recall,
            metrics->combined_metrics.detection.f1_score,
            metrics->combined_metrics.detection.accuracy,
            metrics->combined_metrics.detection.false_positive_rate,
            metrics->combined_metrics.performance.packets_per_second,
            metrics->combined_metrics.performance.gbps_throughput,
            metrics->combined_metrics.gpu.gpu_utilization_percent,
            metrics->combined_metrics.blocking.attack_blocking_rate,
            metrics->combined_metrics.blocking.collateral_damage_rate);
    
    fclose(file);
    printf("Metrics exported to %s\n", filename);
    return 0;
}

int metrics_export_json(system_metrics_t *metrics, const char *filename) {
    FILE *file = fopen(filename, "w");
    if (!file) {
        fprintf(stderr, "Failed to open file for writing: %s\n", filename);
        return -1;
    }
    
    fprintf(file, "{\n");
    fprintf(file, "  \"experiment\": {\n");
    fprintf(file, "    \"dataset\": \"%s\",\n", metrics->dataset_name);
    fprintf(file, "    \"config\": \"%s\",\n", metrics->experiment_config);
    fprintf(file, "    \"duration_us\": %llu,\n", 
            metrics->experiment_end_time - metrics->experiment_start_time);
    fprintf(file, "  },\n");
    
    // Dataset metrics
    fprintf(file, "  \"dataset_metrics\": {\n");
    fprintf(file, "    \"duration_us\": %llu,\n", metrics->dataset.dataset_duration_us);
    fprintf(file, "    \"total_packets\": %llu,\n", metrics->dataset.dataset_total_packets);
    fprintf(file, "    \"total_bytes\": %llu,\n", metrics->dataset.dataset_total_bytes);
    fprintf(file, "    \"packets_per_second\": %.2f,\n", metrics->dataset.dataset_packets_per_second);
    fprintf(file, "    \"gbps\": %.4f\n", metrics->dataset.dataset_gbps);
    fprintf(file, "  },\n");
    
    // Write algorithm metrics
    fprintf(file, "  \"algorithms\": {\n");
    
    // Entropy
    fprintf(file, "    \"entropy\": {\n");
    fprintf(file, "      \"detection\": {\n");
    fprintf(file, "        \"precision\": %.4f,\n", metrics->entropy_metrics.detection.precision);
    fprintf(file, "        \"recall\": %.4f,\n", metrics->entropy_metrics.detection.recall);
    fprintf(file, "        \"f1_score\": %.4f,\n", metrics->entropy_metrics.detection.f1_score);
    fprintf(file, "        \"accuracy\": %.4f,\n", metrics->entropy_metrics.detection.accuracy);
    fprintf(file, "        \"false_positive_rate\": %.4f\n", metrics->entropy_metrics.detection.false_positive_rate);
    fprintf(file, "      },\n");
    fprintf(file, "      \"performance\": {\n");
    fprintf(file, "        \"packets_per_second\": %.2f,\n", metrics->entropy_metrics.performance.packets_per_second);
    fprintf(file, "        \"gbps_throughput\": %.4f,\n", metrics->entropy_metrics.performance.gbps_throughput);
    fprintf(file, "        \"avg_processing_time_us\": %llu\n", metrics->entropy_metrics.performance.avg_processing_time_us);
    fprintf(file, "      },\n");
    fprintf(file, "      \"gpu\": {\n");
    fprintf(file, "        \"utilization_percent\": %.2f,\n", metrics->entropy_metrics.gpu.gpu_utilization_percent);
    fprintf(file, "        \"kernel_time_us\": %llu,\n", metrics->entropy_metrics.gpu.kernel_execution_time_us);
    fprintf(file, "        \"memory_transfer_time_us\": %llu\n", metrics->entropy_metrics.gpu.memory_transfer_time_us);
    fprintf(file, "      },\n");
    fprintf(file, "      \"blocking\": {\n");
    fprintf(file, "        \"attack_blocking_rate\": %.2f,\n", metrics->entropy_metrics.blocking.attack_blocking_rate);
    fprintf(file, "        \"collateral_damage_rate\": %.2f,\n", metrics->entropy_metrics.blocking.collateral_damage_rate);
    fprintf(file, "        \"blocking_efficiency\": %.2f\n", metrics->entropy_metrics.blocking.blocking_efficiency);
    fprintf(file, "      }\n");
    fprintf(file, "    },\n");
    
    // Similar for CUSUM, SVM, and Combined...
    fprintf(file, "  }\n");
    fprintf(file, "}\n");
    
    fclose(file);
    printf("Metrics exported to %s\n", filename);
    return 0;
}

void metrics_calculate_combined_metrics(system_metrics_t *metrics) {
    // Aggregate detection metrics from all algorithms
    metrics->combined_metrics.detection.true_positives = 
        metrics->entropy_metrics.detection.true_positives +
        metrics->cusum_metrics.detection.true_positives +
        metrics->svm_metrics.detection.true_positives;
    
    metrics->combined_metrics.detection.false_positives = 
        metrics->entropy_metrics.detection.false_positives +
        metrics->cusum_metrics.detection.false_positives +
        metrics->svm_metrics.detection.false_positives;
    
    metrics->combined_metrics.detection.true_negatives = 
        metrics->entropy_metrics.detection.true_negatives +
        metrics->cusum_metrics.detection.true_negatives +
        metrics->svm_metrics.detection.true_negatives;
    
    metrics->combined_metrics.detection.false_negatives = 
        metrics->entropy_metrics.detection.false_negatives +
        metrics->cusum_metrics.detection.false_negatives +
        metrics->svm_metrics.detection.false_negatives;
    
    // Calculate combined detection metrics
    metrics_calculate_detection_metrics(&metrics->combined_metrics.detection);
    
    // Aggregate performance metrics
    metrics->combined_metrics.performance.total_packets_processed = 
        metrics->entropy_metrics.performance.total_packets_processed +
        metrics->cusum_metrics.performance.total_packets_processed +
        metrics->svm_metrics.performance.total_packets_processed;
    
    metrics->combined_metrics.performance.total_bytes_processed = 
        metrics->entropy_metrics.performance.total_bytes_processed +
        metrics->cusum_metrics.performance.total_bytes_processed +
        metrics->svm_metrics.performance.total_bytes_processed;
    
    metrics->combined_metrics.performance.total_flows_processed = 
        metrics->entropy_metrics.performance.total_flows_processed +
        metrics->cusum_metrics.performance.total_flows_processed +
        metrics->svm_metrics.performance.total_flows_processed;
    
    metrics->combined_metrics.performance.total_processing_time_us = 
        metrics->entropy_metrics.performance.total_processing_time_us +
        metrics->cusum_metrics.performance.total_processing_time_us +
        metrics->svm_metrics.performance.total_processing_time_us;
    
    // Calculate combined experiment duration (reuse for both performance and GPU metrics)
    uint64_t combined_duration_us = (metrics->experiment_end_time > metrics->experiment_start_time) ?
                                     (metrics->experiment_end_time - metrics->experiment_start_time) : 0;
    
    // Calculate combined performance metrics using experiment duration
    metrics_calculate_performance_metrics(&metrics->combined_metrics.performance, combined_duration_us);
    
    // Aggregate GPU metrics
    metrics->combined_metrics.gpu.kernel_execution_time_us = 
        metrics->entropy_metrics.gpu.kernel_execution_time_us +
        metrics->cusum_metrics.gpu.kernel_execution_time_us +
        metrics->svm_metrics.gpu.kernel_execution_time_us;
    
    metrics->combined_metrics.gpu.memory_transfer_time_us = 
        metrics->entropy_metrics.gpu.memory_transfer_time_us +
        metrics->cusum_metrics.gpu.memory_transfer_time_us +
        metrics->svm_metrics.gpu.memory_transfer_time_us;
    
    metrics->combined_metrics.gpu.total_gpu_time_us = 
        metrics->entropy_metrics.gpu.total_gpu_time_us +
        metrics->cusum_metrics.gpu.total_gpu_time_us +
        metrics->svm_metrics.gpu.total_gpu_time_us;
    
    // Calculate combined GPU metrics using experiment duration
    metrics_calculate_gpu_metrics(&metrics->combined_metrics.gpu, combined_duration_us);
    
    // Aggregate blocking metrics
    metrics->combined_metrics.blocking.total_attack_packets = 
        metrics->entropy_metrics.blocking.total_attack_packets +
        metrics->cusum_metrics.blocking.total_attack_packets +
        metrics->svm_metrics.blocking.total_attack_packets;
    
    metrics->combined_metrics.blocking.attack_packets_blocked = 
        metrics->entropy_metrics.blocking.attack_packets_blocked +
        metrics->cusum_metrics.blocking.attack_packets_blocked +
        metrics->svm_metrics.blocking.attack_packets_blocked;
    
    metrics->combined_metrics.blocking.total_benign_packets = 
        metrics->entropy_metrics.blocking.total_benign_packets +
        metrics->cusum_metrics.blocking.total_benign_packets +
        metrics->svm_metrics.blocking.total_benign_packets;
    
    metrics->combined_metrics.blocking.benign_packets_blocked = 
        metrics->entropy_metrics.blocking.benign_packets_blocked +
        metrics->cusum_metrics.blocking.benign_packets_blocked +
        metrics->svm_metrics.blocking.benign_packets_blocked;
    
    // Calculate combined blocking metrics
    metrics_calculate_blocking_metrics(&metrics->combined_metrics.blocking);
}

void metrics_print_summary(system_metrics_t *metrics) {
    printf("\n=== DDoS Detection System Performance Summary ===\n");
    printf("Dataset: %s\n", metrics->dataset_name);
    printf("Configuration: %s\n", metrics->experiment_config);
    printf("Experiment Duration: %.2f seconds\n", 
           (metrics->experiment_end_time - metrics->experiment_start_time) / 1000000.0);
    
    // Dataset traffic (ground-truth) rate derived from CSV timestamps
    if (metrics->dataset.dataset_packets_per_second > 0.0) {
        printf("Dataset Traffic Rate: %.2f packets/sec (%.4f Gbps)\n",
               metrics->dataset.dataset_packets_per_second,
               metrics->dataset.dataset_gbps);
    } else {
        printf("Dataset Traffic Rate: N/A\n");
    }
    
    printf("\n--- Entropy Detection ---\n");
    printf("Precision: %.4f, Recall: %.4f, F1: %.4f, Accuracy: %.4f, FPR: %.4f\n",
           metrics->entropy_metrics.detection.precision,
           metrics->entropy_metrics.detection.recall,
           metrics->entropy_metrics.detection.f1_score,
           metrics->entropy_metrics.detection.accuracy,
           metrics->entropy_metrics.detection.false_positive_rate);
    if (metrics->entropy_metrics.performance.detection_latency_us > 0) {
        printf("Detection Lead Time: %.2f ms\n", 
               metrics->entropy_metrics.performance.detection_latency_us / 1000.0);
    }
    if (metrics->entropy_metrics.performance.packets_per_second == 0.0) {
        printf("Processing Throughput: N/A (dataset too small for accurate measurement)\n");
    } else {
        printf("Processing Throughput: %.2f packets/sec (%.4f Gbps)\n",
               metrics->entropy_metrics.performance.packets_per_second,
               metrics->entropy_metrics.performance.gbps_throughput);
    }
    if (metrics->entropy_metrics.performance.p95_processing_time_us > 0) {
        printf("95th Percentile Latency: %.2f us\n", 
               (double)metrics->entropy_metrics.performance.p95_processing_time_us);
    }
    printf("GPU Utilization: %.2f%%\n", metrics->entropy_metrics.gpu.gpu_utilization_percent);
    printf("Attack Blocking: %.2f%%, Collateral Damage: %.2f%%\n",
           metrics->entropy_metrics.blocking.attack_blocking_rate,
           metrics->entropy_metrics.blocking.collateral_damage_rate);
    
    printf("\n--- CUSUM Detection ---\n");
    printf("Precision: %.4f, Recall: %.4f, F1: %.4f, Accuracy: %.4f, FPR: %.4f\n",
           metrics->cusum_metrics.detection.precision,
           metrics->cusum_metrics.detection.recall,
           metrics->cusum_metrics.detection.f1_score,
           metrics->cusum_metrics.detection.accuracy,
           metrics->cusum_metrics.detection.false_positive_rate);
    if (metrics->cusum_metrics.performance.detection_latency_us > 0) {
        printf("Detection Lead Time: %.2f ms\n", 
               metrics->cusum_metrics.performance.detection_latency_us / 1000.0);
    }
    if (metrics->cusum_metrics.performance.packets_per_second == 0.0) {
        printf("Processing Throughput: N/A (dataset too small for accurate measurement)\n");
    } else {
        printf("Processing Throughput: %.2f packets/sec (%.4f Gbps)\n",
               metrics->cusum_metrics.performance.packets_per_second,
               metrics->cusum_metrics.performance.gbps_throughput);
    }
    if (metrics->cusum_metrics.performance.p95_processing_time_us > 0) {
        printf("95th Percentile Latency: %.2f us\n", 
               (double)metrics->cusum_metrics.performance.p95_processing_time_us);
    }
    
    printf("\n--- SVM Detection ---\n");
    printf("Precision: %.4f, Recall: %.4f, F1: %.4f, Accuracy: %.4f, FPR: %.4f\n",
           metrics->svm_metrics.detection.precision,
           metrics->svm_metrics.detection.recall,
           metrics->svm_metrics.detection.f1_score,
           metrics->svm_metrics.detection.accuracy,
           metrics->svm_metrics.detection.false_positive_rate);
    if (metrics->svm_metrics.performance.detection_latency_us > 0) {
        printf("Detection Lead Time: %.2f ms\n", 
               metrics->svm_metrics.performance.detection_latency_us / 1000.0);
    }
    if (metrics->svm_metrics.performance.packets_per_second == 0.0) {
        printf("Processing Throughput: N/A (dataset too small for accurate measurement)\n");
    } else {
        printf("Processing Throughput: %.2f packets/sec (%.4f Gbps)\n",
               metrics->svm_metrics.performance.packets_per_second,
               metrics->svm_metrics.performance.gbps_throughput);
    }
    if (metrics->svm_metrics.performance.p95_processing_time_us > 0) {
        printf("95th Percentile Latency: %.2f us\n", 
               (double)metrics->svm_metrics.performance.p95_processing_time_us);
    }
    printf("GPU Utilization: %.2f%%\n", metrics->svm_metrics.gpu.gpu_utilization_percent);
    
    printf("\n--- Combined Detection ---\n");
    printf("Precision: %.4f, Recall: %.4f, F1: %.4f, Accuracy: %.4f\n",
           metrics->combined_metrics.detection.precision,
           metrics->combined_metrics.detection.recall,
           metrics->combined_metrics.detection.f1_score,
           metrics->combined_metrics.detection.accuracy);
    if (metrics->combined_metrics.performance.packets_per_second == 0.0) {
        printf("Processing Throughput: N/A (dataset too small for accurate measurement)\n");
    } else {
        printf("Processing Throughput: %.2f packets/sec (%.4f Gbps)\n",
               metrics->combined_metrics.performance.packets_per_second,
               metrics->combined_metrics.performance.gbps_throughput);
    }
    printf("Attack Blocking: %.2f%%, Collateral Damage: %.2f%%\n",
           metrics->combined_metrics.blocking.attack_blocking_rate,
           metrics->combined_metrics.blocking.collateral_damage_rate);
}

uint64_t metrics_get_current_time_us(void) {
#ifdef _WIN32
    LARGE_INTEGER frequency, counter;
    QueryPerformanceFrequency(&frequency);
    QueryPerformanceCounter(&counter);
    return (uint64_t)((counter.QuadPart * 1000000ULL) / frequency.QuadPart);
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000ULL + tv.tv_usec;
#endif
}

void metrics_add_processing_time(performance_metrics_t *metrics, uint64_t time_us) {
    // Simple implementation - in a real system, you'd maintain a sorted list
    // for percentile calculations
    static uint64_t times[10000];
    static size_t time_count = 0;
    
    if (time_count < sizeof(times) / sizeof(times[0])) {
        times[time_count++] = time_us;
    }
    
    // Calculate percentiles (simplified)
    if (time_count > 0) {
        // Sort times array (bubble sort for simplicity)
        for (size_t i = 0; i < time_count - 1; i++) {
            for (size_t j = 0; j < time_count - i - 1; j++) {
                if (times[j] > times[j + 1]) {
                    uint64_t temp = times[j];
                    times[j] = times[j + 1];
                    times[j + 1] = temp;
                }
            }
        }
        
        // Calculate percentiles
        size_t p95_idx = (size_t)(time_count * 0.95);
        size_t p99_idx = (size_t)(time_count * 0.99);
        
        if (p95_idx < time_count) metrics->p95_processing_time_us = times[p95_idx];
        if (p99_idx < time_count) metrics->p99_processing_time_us = times[p99_idx];
    }
}

void metrics_update_throughput(performance_metrics_t *metrics, uint32_t packets, 
                              uint32_t bytes, uint64_t time_us) {
    metrics->total_packets_processed += packets;
    metrics->total_bytes_processed += bytes;
    metrics->total_flows_processed++;
    
    if (time_us > 0) {
        double time_sec = time_us / 1000000.0;
        metrics->packets_per_second = packets / time_sec;
        metrics->bytes_per_second = bytes / time_sec;
        metrics->gbps_throughput = (metrics->bytes_per_second * 8) / (1024 * 1024 * 1024);
    }
}

void metrics_compare_algorithms(system_metrics_t *metrics) {
    printf("\n=== Algorithm Comparison ===\n");
    
    // Find best performing algorithm for each metric
    double best_f1 = 0;
    char best_f1_name[32] = "None";
    
    if (metrics->entropy_metrics.detection.f1_score > best_f1) {
        best_f1 = metrics->entropy_metrics.detection.f1_score;
        strcpy(best_f1_name, "Entropy");
    }
    if (metrics->cusum_metrics.detection.f1_score > best_f1) {
        best_f1 = metrics->cusum_metrics.detection.f1_score;
        strcpy(best_f1_name, "CUSUM");
    }
    if (metrics->svm_metrics.detection.f1_score > best_f1) {
        best_f1 = metrics->svm_metrics.detection.f1_score;
        strcpy(best_f1_name, "SVM");
    }
    
    printf("Best F1-Score: %s (%.4f)\n", best_f1_name, best_f1);
    
    // Calculate speedup
    double entropy_speedup = metrics_calculate_speedup(&metrics->cusum_metrics, &metrics->entropy_metrics);
    double svm_speedup = metrics_calculate_speedup(&metrics->cusum_metrics, &metrics->svm_metrics);
    
    printf("GPU Speedup vs CPU:\n");
    printf("  Entropy: %.2fx\n", entropy_speedup);
    printf("  SVM: %.2fx\n", svm_speedup);
}

double metrics_calculate_speedup(algorithm_metrics_t *cpu_metrics, 
                               algorithm_metrics_t *gpu_metrics) {
    if (cpu_metrics->performance.avg_processing_time_us > 0 && 
        gpu_metrics->performance.avg_processing_time_us > 0) {
        return (double)cpu_metrics->performance.avg_processing_time_us / 
               gpu_metrics->performance.avg_processing_time_us;
    }
    return 1.0;
}
