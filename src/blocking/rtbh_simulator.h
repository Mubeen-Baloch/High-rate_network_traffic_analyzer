#ifndef RTBH_SIMULATOR_H
#define RTBH_SIMULATOR_H

#include "traffic_parser.h"
#include "metrics.h"

// RTBH (Remote Triggered Black Hole) configuration
typedef struct {
    uint32_t max_blacklist_size;  // Maximum number of IPs in blacklist
    uint64_t blacklist_timeout_ms; // Timeout for blacklist entries
    int enable_logging;          // Enable detailed logging
    float threshold_packets;      // Minimum packets to trigger blacklisting
} rtbh_config_t;

// Blacklist entry
typedef struct {
    uint32_t ip_address;         // Blacklisted IP address
    uint64_t timestamp;           // When it was added
    uint32_t packet_count;       // Number of packets that triggered blacklisting
    uint32_t byte_count;         // Number of bytes that triggered blacklisting
    char reason[64];             // Reason for blacklisting
} blacklist_entry_t;

// RTBH simulator state
typedef struct {
    rtbh_config_t config;
    
    // Blacklist management
    blacklist_entry_t *blacklist;
    uint32_t blacklist_count;
    uint32_t blacklist_capacity;
    
    // Statistics
    uint32_t total_blocked_packets;
    uint32_t total_blocked_bytes;
    uint32_t total_blocked_flows;
    uint32_t false_positives;    // Legitimate traffic blocked
    uint32_t true_positives;     // Attack traffic blocked
    
    // Metrics
    algorithm_metrics_t *metrics;
} rtbh_simulator_t;

// Function declarations
int rtbh_simulator_init(rtbh_simulator_t *simulator, const rtbh_config_t *config, 
                        algorithm_metrics_t *metrics);
void rtbh_simulator_cleanup(rtbh_simulator_t *simulator);

// Blacklist management
int rtbh_add_to_blacklist(rtbh_simulator_t *simulator, uint32_t ip_address, 
                          uint32_t packet_count, uint32_t byte_count, const char *reason);
int rtbh_remove_from_blacklist(rtbh_simulator_t *simulator, uint32_t ip_address);
int rtbh_is_blacklisted(rtbh_simulator_t *simulator, uint32_t ip_address);
int rtbh_cleanup_expired_entries(rtbh_simulator_t *simulator);

// Traffic processing
int rtbh_process_flows(rtbh_simulator_t *simulator, flow_collection_t *flows);
int rtbh_process_window(rtbh_simulator_t *simulator, time_window_t *window);
int rtbh_block_traffic(rtbh_simulator_t *simulator, network_flow_t *flow);

// Decision making
int rtbh_should_blacklist_ip(rtbh_simulator_t *simulator, uint32_t ip_address, 
                             uint32_t packet_count, uint32_t byte_count);
int rtbh_analyze_traffic_patterns(rtbh_simulator_t *simulator, time_window_t *window);

// Configuration functions
void rtbh_get_default_config(rtbh_config_t *config);
void rtbh_set_config(rtbh_simulator_t *simulator, const rtbh_config_t *config);

// Analysis and reporting
int rtbh_analyze_blocking_effectiveness(rtbh_simulator_t *simulator, time_window_t *window);
void rtbh_print_statistics(rtbh_simulator_t *simulator);
void rtbh_print_blacklist(rtbh_simulator_t *simulator);

// Utility functions
uint32_t rtbh_calculate_ip_score(uint32_t packet_count, uint32_t byte_count, 
                                 uint32_t flow_count);
const char* rtbh_get_ip_string(uint32_t ip_address);

#endif // RTBH_SIMULATOR_H
