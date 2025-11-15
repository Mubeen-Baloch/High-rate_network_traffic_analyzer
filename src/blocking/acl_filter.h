#ifndef ACL_FILTER_H
#define ACL_FILTER_H

#include "traffic_parser.h"
#include "metrics.h"

// ACL rule structure
typedef struct {
    uint32_t src_ip;           // Source IP (0 = any)
    uint32_t dst_ip;           // Destination IP (0 = any)
    uint16_t src_port;         // Source port (0 = any)
    uint16_t dst_port;         // Destination port (0 = any)
    uint8_t protocol;          // Protocol (0 = any)
    uint8_t action;            // Action: 0=ALLOW, 1=DENY
    uint32_t priority;         // Rule priority (higher = more important)
    char description[64];      // Rule description
} acl_rule_t;

// ACL filter configuration
typedef struct {
    uint32_t max_rules;        // Maximum number of rules
    int enable_logging;        // Enable detailed logging
    int auto_generate_rules;   // Auto-generate rules from detections
    float rule_threshold;      // Threshold for auto-generating rules
} acl_config_t;

// ACL filter state
typedef struct {
    acl_config_t config;
    
    // Rule management
    acl_rule_t *rules;
    uint32_t rule_count;
    uint32_t rule_capacity;
    
    // Statistics
    uint32_t total_packets_processed;
    uint32_t total_packets_allowed;
    uint32_t total_packets_denied;
    uint32_t total_bytes_allowed;
    uint32_t total_bytes_denied;
    uint32_t rule_matches;
    
    // Metrics
    algorithm_metrics_t *metrics;
} acl_filter_t;

// Function declarations
int acl_filter_init(acl_filter_t *filter, const acl_config_t *config, 
                   algorithm_metrics_t *metrics);
void acl_filter_cleanup(acl_filter_t *filter);

// Rule management
int acl_add_rule(acl_filter_t *filter, const acl_rule_t *rule);
int acl_remove_rule(acl_filter_t *filter, uint32_t rule_index);
int acl_clear_rules(acl_filter_t *filter);
int acl_auto_generate_rule(acl_filter_t *filter, network_flow_t *flow, 
                          const char *reason);

// Traffic processing
int acl_process_flows(acl_filter_t *filter, flow_collection_t *flows);
int acl_process_window(acl_filter_t *filter, time_window_t *window);
int acl_process_flow(acl_filter_t *filter, network_flow_t *flow);

// Rule matching
int acl_match_rule(acl_filter_t *filter, network_flow_t *flow, acl_rule_t **matched_rule);
int acl_ip_matches(uint32_t rule_ip, uint32_t flow_ip);
int acl_port_matches(uint16_t rule_port, uint16_t flow_port);
int acl_protocol_matches(uint8_t rule_protocol, uint8_t flow_protocol);

// Configuration functions
void acl_get_default_config(acl_config_t *config);
void acl_set_config(acl_filter_t *filter, const acl_config_t *config);

// Analysis and reporting
void acl_print_statistics(acl_filter_t *filter);
void acl_print_rules(acl_filter_t *filter);
int acl_analyze_filtering_effectiveness(acl_filter_t *filter, time_window_t *window);

// Utility functions
const char* acl_get_action_string(uint8_t action);
const char* acl_get_protocol_string(uint8_t protocol);
const char* acl_get_ip_string(uint32_t ip_address);

#endif // ACL_FILTER_H
