#ifndef METRICS_H
#define METRICS_H

#include <stdint.h>
#include <time.h>

// Detection accuracy metrics
typedef struct {
    uint32_t true_positives;   // Correctly detected attacks
    uint32_t false_positives;  // False alarms (benign flagged as attack)
    uint32_t true_negatives;   // Correctly identified benign traffic
    uint32_t false_negatives; // Missed attacks (attack flagged as benign)
    
    double precision;          // TP / (TP + FP)
    double recall;             // TP / (TP + FN)
    double f1_score;          // 2 * (precision * recall) / (precision + recall)
    double accuracy;          // (TP + TN) / (TP + TN + FP + FN)
    double false_positive_rate; // FP / (FP + TN)
} detection_metrics_t;

// Timing and performance metrics
typedef struct {
    uint64_t total_packets_processed;
    uint64_t total_bytes_processed;
    uint64_t total_flows_processed;
    
    double packets_per_second;
    double bytes_per_second;
    double flows_per_second;
    double gbps_throughput;
    
    uint64_t detection_latency_us;     // Time from attack start to detection
    uint64_t avg_processing_time_us;   // Average time per packet/flow
    uint64_t p95_processing_time_us;    // 95th percentile processing time
    uint64_t p99_processing_time_us;    // 99th percentile processing time
    
    uint64_t total_processing_time_us;
    uint64_t gpu_kernel_time_us;
    uint64_t memory_transfer_time_us;
} performance_metrics_t;

// GPU utilization metrics
typedef struct {
    double gpu_utilization_percent;
    double memory_utilization_percent;
    uint64_t kernel_execution_time_us;
    uint64_t memory_transfer_time_us;
    uint64_t total_gpu_time_us;
    
    size_t kernel_calls;
    size_t memory_transfers;
    size_t bytes_transferred;
} gpu_metrics_t;

// Blocking effectiveness metrics
typedef struct {
    uint32_t attack_packets_blocked;
    uint32_t attack_bytes_blocked;
    uint32_t benign_packets_blocked;    // Collateral damage
    uint32_t benign_bytes_blocked;
    
    uint32_t total_attack_packets;
    uint32_t total_attack_bytes;
    uint32_t total_benign_packets;
    uint32_t total_benign_bytes;
    
    double attack_blocking_rate;        // % of attack traffic blocked
    double collateral_damage_rate;      // % of benign traffic blocked
    double blocking_efficiency;         // Attack blocked / (Attack blocked + Benign blocked)
} blocking_metrics_t;

// Algorithm-specific metrics
typedef struct {
    char algorithm_name[32];
    detection_metrics_t detection;
    performance_metrics_t performance;
    gpu_metrics_t gpu;
    blocking_metrics_t blocking;
    
    uint64_t start_time;
    uint64_t end_time;
    uint32_t alerts_generated;
    uint32_t false_alarms;
} algorithm_metrics_t;

// Overall system metrics
typedef struct {
    algorithm_metrics_t entropy_metrics;
    algorithm_metrics_t cusum_metrics;
    algorithm_metrics_t svm_metrics;
    algorithm_metrics_t combined_metrics;
    
    uint64_t experiment_start_time;
    uint64_t experiment_end_time;
    uint32_t total_experiments;
    char dataset_name[64];
    char experiment_config[128];
} system_metrics_t;

// Metrics collection functions
void metrics_init(system_metrics_t *metrics);
void metrics_start_experiment(system_metrics_t *metrics, const char *dataset_name, 
                             const char *config);
void metrics_end_experiment(system_metrics_t *metrics);

// Algorithm-specific metrics
void metrics_start_algorithm(algorithm_metrics_t *metrics, const char *algorithm_name);
void metrics_end_algorithm(algorithm_metrics_t *metrics);
void metrics_record_detection(algorithm_metrics_t *metrics, int is_attack, 
                             int detected_as_attack);
void metrics_record_processing_time(algorithm_metrics_t *metrics, uint64_t processing_time_us);
void metrics_record_gpu_time(algorithm_metrics_t *metrics, uint64_t kernel_time_us, 
                           uint64_t transfer_time_us);
void metrics_record_blocking(algorithm_metrics_t *metrics, int is_attack, 
                           int was_blocked, uint32_t packet_count, uint32_t byte_count);

// Calculation functions
void metrics_calculate_detection_metrics(detection_metrics_t *metrics);
void metrics_calculate_performance_metrics(performance_metrics_t *metrics);
void metrics_calculate_gpu_metrics(gpu_metrics_t *metrics);
void metrics_calculate_blocking_metrics(blocking_metrics_t *metrics);
void metrics_calculate_combined_metrics(system_metrics_t *metrics);

// Export functions
int metrics_export_csv(system_metrics_t *metrics, const char *filename);
int metrics_export_json(system_metrics_t *metrics, const char *filename);
void metrics_print_summary(system_metrics_t *metrics);

// Utility functions
uint64_t metrics_get_current_time_us(void);
void metrics_add_processing_time(performance_metrics_t *metrics, uint64_t time_us);
void metrics_update_throughput(performance_metrics_t *metrics, uint32_t packets, 
                              uint32_t bytes, uint64_t time_us);

// Comparison functions
void metrics_compare_algorithms(system_metrics_t *metrics);
double metrics_calculate_speedup(algorithm_metrics_t *cpu_metrics, 
                                algorithm_metrics_t *gpu_metrics);

#endif // METRICS_H
