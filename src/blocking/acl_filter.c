#include "acl_filter.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void acl_get_default_config(acl_config_t *config) {
    config->max_rules = 1000;           // Maximum 1000 rules
    config->enable_logging = 1;         // Enable logging
    config->auto_generate_rules = 1;    // Auto-generate rules
    config->rule_threshold = 0.8f;       // Threshold for auto-generation
}

int acl_filter_init(acl_filter_t *filter, const acl_config_t *config, 
                   algorithm_metrics_t *metrics) {
    memset(filter, 0, sizeof(acl_filter_t));
    
    filter->metrics = metrics;
    
    if (config) {
        filter->config = *config;
    } else {
        acl_get_default_config(&filter->config);
    }
    
    // Initialize rules array
    filter->rule_capacity = filter->config.max_rules;
    filter->rules = (acl_rule_t*)malloc(filter->rule_capacity * sizeof(acl_rule_t));
    
    if (!filter->rules) {
        fprintf(stderr, "Failed to allocate ACL rules array\n");
        return -1;
    }
    
    filter->rule_count = 0;
    
    // Add default rules
    acl_rule_t default_rule;
    memset(&default_rule, 0, sizeof(default_rule));
    default_rule.action = 0; // ALLOW
    default_rule.priority = 0;
    strcpy(default_rule.description, "Default allow rule");
    acl_add_rule(filter, &default_rule);
    
    printf("ACL filter initialized successfully\n");
    printf("  Max rules: %u\n", filter->config.max_rules);
    printf("  Auto-generate rules: %s\n", filter->config.auto_generate_rules ? "Yes" : "No");
    printf("  Rule threshold: %.2f\n", filter->config.rule_threshold);
    
    return 0;
}

void acl_filter_cleanup(acl_filter_t *filter) {
    if (filter->rules) {
        free(filter->rules);
        filter->rules = NULL;
    }
    
    memset(filter, 0, sizeof(acl_filter_t));
}

int acl_add_rule(acl_filter_t *filter, const acl_rule_t *rule) {
    if (!filter || !rule) return -1;
    
    if (filter->rule_count >= filter->rule_capacity) {
        fprintf(stderr, "ACL filter: Maximum rules reached\n");
        return -1;
    }
    
    // Insert rule in priority order
    uint32_t insert_pos = filter->rule_count;
    for (uint32_t i = 0; i < filter->rule_count; i++) {
        if (rule->priority > filter->rules[i].priority) {
            insert_pos = i;
            break;
        }
    }
    
    // Shift rules to make space
    if (insert_pos < filter->rule_count) {
        memmove(&filter->rules[insert_pos + 1], &filter->rules[insert_pos], 
                (filter->rule_count - insert_pos) * sizeof(acl_rule_t));
    }
    
    // Insert new rule
    filter->rules[insert_pos] = *rule;
    filter->rule_count++;
    
    if (filter->config.enable_logging) {
        printf("ACL: Added rule %u (priority: %u, action: %s)\n", 
               filter->rule_count - 1, rule->priority, acl_get_action_string(rule->action));
    }
    
    return 0;
}

int acl_remove_rule(acl_filter_t *filter, uint32_t rule_index) {
    if (!filter || rule_index >= filter->rule_count) return -1;
    
    // Shift rules to remove the specified rule
    memmove(&filter->rules[rule_index], &filter->rules[rule_index + 1], 
            (filter->rule_count - rule_index - 1) * sizeof(acl_rule_t));
    
    filter->rule_count--;
    
    if (filter->config.enable_logging) {
        printf("ACL: Removed rule %u\n", rule_index);
    }
    
    return 0;
}

int acl_clear_rules(acl_filter_t *filter) {
    if (!filter) return -1;
    
    filter->rule_count = 0;
    
    if (filter->config.enable_logging) {
        printf("ACL: Cleared all rules\n");
    }
    
    return 0;
}

int acl_auto_generate_rule(acl_filter_t *filter, network_flow_t *flow, 
                          const char *reason) {
    if (!filter || !flow || !filter->config.auto_generate_rules) return -1;
    
    acl_rule_t new_rule;
    memset(&new_rule, 0, sizeof(new_rule));
    
    // Generate rule based on flow characteristics
    new_rule.src_ip = flow->src_ip;
    new_rule.dst_ip = flow->dst_ip;
    new_rule.src_port = flow->src_port;
    new_rule.dst_port = flow->dst_port;
    new_rule.protocol = flow->protocol;
    new_rule.action = 1; // DENY
    new_rule.priority = 100; // High priority
    snprintf(new_rule.description, sizeof(new_rule.description), 
             "Auto-generated: %s", reason);
    
    return acl_add_rule(filter, &new_rule);
}

int acl_process_flows(acl_filter_t *filter, flow_collection_t *flows) {
    if (!filter || !flows) return -1;
    
    uint64_t start_time = metrics_get_current_time_us();
    
    // Create time windows
    time_window_t *windows;
    size_t window_count;
    
    if (create_time_windows(flows, &windows, &window_count, 1000) != 0) { // 1 second windows
        fprintf(stderr, "Failed to create time windows\n");
        return -1;
    }
    
    printf("Processing %zu flows in %zu time windows with ACL filter\n", flows->count, window_count);
    
    // Process each window
    for (size_t i = 0; i < window_count; i++) {
        if (windows[i].flow_count > 0) {
            if (acl_process_window(filter, &windows[i]) != 0) {
                fprintf(stderr, "Failed to process window %zu\n", i);
                free_time_windows(windows, window_count);
                return -1;
            }
        }
    }
    
    uint64_t end_time = metrics_get_current_time_us();
    if (filter->metrics) {
        metrics_record_processing_time(filter->metrics, end_time - start_time);
    }
    
    free_time_windows(windows, window_count);
    return 0;
}

int acl_process_window(acl_filter_t *filter, time_window_t *window) {
    if (!filter || !window) return -1;
    
    // Process each flow in the window
    for (size_t i = 0; i < window->flow_count; i++) {
        if (acl_process_flow(filter, &window->flows[i]) != 0) {
            fprintf(stderr, "Failed to process flow %zu\n", i);
            return -1;
        }
    }
    
    return 0;
}

int acl_process_flow(acl_filter_t *filter, network_flow_t *flow) {
    if (!filter || !flow) return -1;
    
    acl_rule_t *matched_rule = NULL;
    
    // Find matching rule
    if (acl_match_rule(filter, flow, &matched_rule) != 0) {
        fprintf(stderr, "Failed to match rule\n");
        return -1;
    }
    
    filter->total_packets_processed += flow->total_fwd_packets + flow->total_bwd_packets;
    
    if (matched_rule) {
        filter->rule_matches++;
        
        if (matched_rule->action == 0) { // ALLOW
            filter->total_packets_allowed += flow->total_fwd_packets + flow->total_bwd_packets;
            filter->total_bytes_allowed += flow->total_fwd_bytes + flow->total_bwd_bytes;
            
            if (filter->config.enable_logging) {
                printf("ACL: ALLOWED flow from %s:%u to %s:%u (protocol: %s)\n",
                       acl_get_ip_string(flow->src_ip), flow->src_port,
                       acl_get_ip_string(flow->dst_ip), flow->dst_port,
                       acl_get_protocol_string(flow->protocol));
            }
        } else { // DENY
            filter->total_packets_denied += flow->total_fwd_packets + flow->total_bwd_packets;
            filter->total_bytes_denied += flow->total_fwd_bytes + flow->total_bwd_bytes;
            
            if (filter->config.enable_logging) {
                printf("ACL: DENIED flow from %s:%u to %s:%u (protocol: %s)\n",
                       acl_get_ip_string(flow->src_ip), flow->src_port,
                       acl_get_ip_string(flow->dst_ip), flow->dst_port,
                       acl_get_protocol_string(flow->protocol));
            }
        }
        
        // Update metrics
        if (filter->metrics) {
            int is_attack = is_attack_flow(flow);
            int was_blocked = (matched_rule->action == 1) ? 1 : 0;
            
            metrics_record_blocking(filter->metrics, is_attack, was_blocked, 
                                   flow->total_fwd_packets + flow->total_bwd_packets,
                                   flow->total_fwd_bytes + flow->total_bwd_bytes);
        }
    } else {
        // No rule matched - use default action (ALLOW)
        filter->total_packets_allowed += flow->total_fwd_packets + flow->total_bwd_packets;
        filter->total_bytes_allowed += flow->total_fwd_bytes + flow->total_bwd_bytes;
    }
    
    return 0;
}

int acl_match_rule(acl_filter_t *filter, network_flow_t *flow, acl_rule_t **matched_rule) {
    if (!filter || !flow || !matched_rule) return -1;
    
    *matched_rule = NULL;
    
    // Check rules in priority order
    for (uint32_t i = 0; i < filter->rule_count; i++) {
        acl_rule_t *rule = &filter->rules[i];
        
        // Check if rule matches
        if (acl_ip_matches(rule->src_ip, flow->src_ip) &&
            acl_ip_matches(rule->dst_ip, flow->dst_ip) &&
            acl_port_matches(rule->src_port, flow->src_port) &&
            acl_port_matches(rule->dst_port, flow->dst_port) &&
            acl_protocol_matches(rule->protocol, flow->protocol)) {
            
            *matched_rule = rule;
            return 0;
        }
    }
    
    return 0; // No rule matched
}

int acl_ip_matches(uint32_t rule_ip, uint32_t flow_ip) {
    // 0 means "any" IP
    return (rule_ip == 0 || rule_ip == flow_ip);
}

int acl_port_matches(uint16_t rule_port, uint16_t flow_port) {
    // 0 means "any" port
    return (rule_port == 0 || rule_port == flow_port);
}

int acl_protocol_matches(uint8_t rule_protocol, uint8_t flow_protocol) {
    // 0 means "any" protocol
    return (rule_protocol == 0 || rule_protocol == flow_protocol);
}

void acl_print_statistics(acl_filter_t *filter) {
    printf("\n=== ACL Filter Statistics ===\n");
    printf("Configuration:\n");
    printf("  Max Rules: %u\n", filter->config.max_rules);
    printf("  Auto-generate Rules: %s\n", filter->config.auto_generate_rules ? "Yes" : "No");
    printf("  Rule Threshold: %.2f\n", filter->config.rule_threshold);
    printf("  Logging Enabled: %s\n", filter->config.enable_logging ? "Yes" : "No");
    
    printf("Current State:\n");
    printf("  Active Rules: %u\n", filter->rule_count);
    printf("  Total Packets Processed: %u\n", filter->total_packets_processed);
    printf("  Packets Allowed: %u\n", filter->total_packets_allowed);
    printf("  Packets Denied: %u\n", filter->total_packets_denied);
    printf("  Bytes Allowed: %u\n", filter->total_bytes_allowed);
    printf("  Bytes Denied: %u\n", filter->total_bytes_denied);
    printf("  Rule Matches: %u\n", filter->rule_matches);
    
    if (filter->total_packets_processed > 0) {
        printf("  Allow Rate: %.2f%%\n", 
               (float)filter->total_packets_allowed / filter->total_packets_processed * 100.0f);
        printf("  Deny Rate: %.2f%%\n", 
               (float)filter->total_packets_denied / filter->total_packets_processed * 100.0f);
    }
}

void acl_print_rules(acl_filter_t *filter) {
    if (!filter) return;
    
    printf("\n=== ACL Rules ===\n");
    printf("Total Rules: %u\n", filter->rule_count);
    
    for (uint32_t i = 0; i < filter->rule_count; i++) {
        acl_rule_t *rule = &filter->rules[i];
        
        printf("Rule %u: %s %s:%u -> %s:%u (%s) [Priority: %u]\n",
               i, acl_get_action_string(rule->action),
               acl_get_ip_string(rule->src_ip), rule->src_port,
               acl_get_ip_string(rule->dst_ip), rule->dst_port,
               acl_get_protocol_string(rule->protocol),
               rule->priority);
        printf("  Description: %s\n", rule->description);
    }
}

int acl_analyze_filtering_effectiveness(acl_filter_t *filter, time_window_t *window) {
    if (!filter || !window) return -1;
    
    // Analysis is done in process_flow function
    return 0;
}

const char* acl_get_action_string(uint8_t action) {
    return (action == 0) ? "ALLOW" : "DENY";
}

const char* acl_get_protocol_string(uint8_t protocol) {
    switch (protocol) {
        case 1: return "ICMP";
        case 6: return "TCP";
        case 17: return "UDP";
        default: return "UNKNOWN";
    }
}

const char* acl_get_ip_string(uint32_t ip_address) {
    static char ip_str[16];
    if (ip_address == 0) {
        strcpy(ip_str, "ANY");
    } else {
        sprintf(ip_str, "%d.%d.%d.%d", 
                (ip_address >> 24) & 0xFF, (ip_address >> 16) & 0xFF, 
                (ip_address >> 8) & 0xFF, ip_address & 0xFF);
    }
    return ip_str;
}

void acl_set_config(acl_filter_t *filter, const acl_config_t *config) {
    if (filter && config) {
        filter->config = *config;
    }
}
