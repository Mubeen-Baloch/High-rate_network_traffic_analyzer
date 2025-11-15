#include "rtbh_simulator.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void rtbh_get_default_config(rtbh_config_t *config) {
    config->max_blacklist_size = 10000;      // Maximum 10K IPs in blacklist
    config->blacklist_timeout_ms = 300000;   // 5 minutes timeout
    config->enable_logging = 1;              // Enable logging
    config->threshold_packets = 1000;        // Minimum packets to trigger blacklisting
}

int rtbh_simulator_init(rtbh_simulator_t *simulator, const rtbh_config_t *config, 
                       algorithm_metrics_t *metrics) {
    memset(simulator, 0, sizeof(rtbh_simulator_t));
    
    simulator->metrics = metrics;
    
    if (config) {
        simulator->config = *config;
    } else {
        rtbh_get_default_config(&simulator->config);
    }
    
    // Initialize blacklist
    simulator->blacklist_capacity = simulator->config.max_blacklist_size;
    simulator->blacklist = (blacklist_entry_t*)malloc(
        simulator->blacklist_capacity * sizeof(blacklist_entry_t));
    
    if (!simulator->blacklist) {
        fprintf(stderr, "Failed to allocate blacklist\n");
        return -1;
    }
    
    simulator->blacklist_count = 0;
    
    printf("RTBH simulator initialized successfully\n");
    printf("  Max blacklist size: %u\n", simulator->config.max_blacklist_size);
    printf("  Blacklist timeout: %llu ms\n", simulator->config.blacklist_timeout_ms);
    printf("  Packet threshold: %.0f\n", simulator->config.threshold_packets);
    
    return 0;
}

void rtbh_simulator_cleanup(rtbh_simulator_t *simulator) {
    if (simulator->blacklist) {
        free(simulator->blacklist);
        simulator->blacklist = NULL;
    }
    
    memset(simulator, 0, sizeof(rtbh_simulator_t));
}

int rtbh_add_to_blacklist(rtbh_simulator_t *simulator, uint32_t ip_address, 
                          uint32_t packet_count, uint32_t byte_count, const char *reason) {
    if (!simulator) return -1;
    
    // Check if already blacklisted
    if (rtbh_is_blacklisted(simulator, ip_address)) {
        return 0; // Already blacklisted
    }
    
    // Check capacity
    if (simulator->blacklist_count >= simulator->blacklist_capacity) {
        // Remove oldest entry
        memmove(&simulator->blacklist[0], &simulator->blacklist[1], 
                (simulator->blacklist_count - 1) * sizeof(blacklist_entry_t));
        simulator->blacklist_count--;
    }
    
    // Add new entry
    blacklist_entry_t *entry = &simulator->blacklist[simulator->blacklist_count];
    entry->ip_address = ip_address;
    entry->timestamp = metrics_get_current_time_us();
    entry->packet_count = packet_count;
    entry->byte_count = byte_count;
    strncpy(entry->reason, reason, sizeof(entry->reason) - 1);
    entry->reason[sizeof(entry->reason) - 1] = '\0';
    
    simulator->blacklist_count++;
    
    if (simulator->config.enable_logging) {
        char ip_str[16];
        rtbh_get_ip_string(ip_address);
        printf("RTBH: Added %s to blacklist (packets: %u, bytes: %u, reason: %s)\n", 
               ip_str, packet_count, byte_count, reason);
    }
    
    return 0;
}

int rtbh_remove_from_blacklist(rtbh_simulator_t *simulator, uint32_t ip_address) {
    if (!simulator) return -1;
    
    for (uint32_t i = 0; i < simulator->blacklist_count; i++) {
        if (simulator->blacklist[i].ip_address == ip_address) {
            // Remove entry by shifting remaining entries
            memmove(&simulator->blacklist[i], &simulator->blacklist[i + 1], 
                    (simulator->blacklist_count - i - 1) * sizeof(blacklist_entry_t));
            simulator->blacklist_count--;
            
            if (simulator->config.enable_logging) {
                char ip_str[16];
                rtbh_get_ip_string(ip_address);
                printf("RTBH: Removed %s from blacklist\n", ip_str);
            }
            
            return 0;
        }
    }
    
    return -1; // Not found
}

int rtbh_is_blacklisted(rtbh_simulator_t *simulator, uint32_t ip_address) {
    if (!simulator) return 0;
    
    for (uint32_t i = 0; i < simulator->blacklist_count; i++) {
        if (simulator->blacklist[i].ip_address == ip_address) {
            return 1; // Found in blacklist
        }
    }
    
    return 0; // Not blacklisted
}

int rtbh_cleanup_expired_entries(rtbh_simulator_t *simulator) {
    if (!simulator) return -1;
    
    uint64_t current_time = metrics_get_current_time_us();
    uint64_t timeout_us = simulator->config.blacklist_timeout_ms * 1000;
    
    uint32_t removed_count = 0;
    
    for (uint32_t i = 0; i < simulator->blacklist_count; i++) {
        if (current_time - simulator->blacklist[i].timestamp > timeout_us) {
            // Remove expired entry
            memmove(&simulator->blacklist[i], &simulator->blacklist[i + 1], 
                    (simulator->blacklist_count - i - 1) * sizeof(blacklist_entry_t));
            simulator->blacklist_count--;
            removed_count++;
            i--; // Check same index again
        }
    }
    
    if (removed_count > 0 && simulator->config.enable_logging) {
        printf("RTBH: Removed %u expired entries from blacklist\n", removed_count);
    }
    
    return 0;
}

int rtbh_process_flows(rtbh_simulator_t *simulator, flow_collection_t *flows) {
    if (!simulator || !flows) return -1;
    
    uint64_t start_time = metrics_get_current_time_us();
    
    // Create time windows
    time_window_t *windows;
    size_t window_count;
    
    if (create_time_windows(flows, &windows, &window_count, 1000) != 0) { // 1 second windows
        fprintf(stderr, "Failed to create time windows\n");
        return -1;
    }
    
    printf("Processing %zu flows in %zu time windows with RTBH\n", flows->count, window_count);
    
    // Process each window
    for (size_t i = 0; i < window_count; i++) {
        if (windows[i].flow_count > 0) {
            if (rtbh_process_window(simulator, &windows[i]) != 0) {
                fprintf(stderr, "Failed to process window %zu\n", i);
                free_time_windows(windows, window_count);
                return -1;
            }
        }
    }
    
    uint64_t end_time = metrics_get_current_time_us();
    if (simulator->metrics) {
        metrics_record_processing_time(simulator->metrics, end_time - start_time);
    }
    
    free_time_windows(windows, window_count);
    return 0;
}

int rtbh_process_window(rtbh_simulator_t *simulator, time_window_t *window) {
    if (!simulator || !window) return -1;
    
    // Cleanup expired entries
    rtbh_cleanup_expired_entries(simulator);
    
    // Analyze traffic patterns to identify suspicious IPs
    if (rtbh_analyze_traffic_patterns(simulator, window) != 0) {
        fprintf(stderr, "Failed to analyze traffic patterns\n");
        return -1;
    }
    
    // Process each flow for blocking
    for (size_t i = 0; i < window->flow_count; i++) {
        if (rtbh_block_traffic(simulator, &window->flows[i]) != 0) {
            fprintf(stderr, "Failed to process flow %zu\n", i);
            return -1;
        }
    }
    
    return 0;
}

int rtbh_block_traffic(rtbh_simulator_t *simulator, network_flow_t *flow) {
    if (!simulator || !flow) return -1;
    
    int src_blocked = rtbh_is_blacklisted(simulator, flow->src_ip);
    int dst_blocked = rtbh_is_blacklisted(simulator, flow->dst_ip);
    
    if (src_blocked || dst_blocked) {
        // Block this traffic
        simulator->total_blocked_packets += flow->total_fwd_packets + flow->total_bwd_packets;
        simulator->total_blocked_bytes += flow->total_fwd_bytes + flow->total_bwd_bytes;
        simulator->total_blocked_flows++;
        
        // Update metrics
        if (simulator->metrics) {
            int is_attack = is_attack_flow(flow);
            int was_blocked = 1;
            
            metrics_record_blocking(simulator->metrics, is_attack, was_blocked, 
                                   flow->total_fwd_packets + flow->total_bwd_packets,
                                   flow->total_fwd_bytes + flow->total_bwd_bytes);
            
            if (is_attack) {
                simulator->true_positives++;
            } else {
                simulator->false_positives++;
            }
        }
        
        if (simulator->config.enable_logging) {
            char src_ip_str[16], dst_ip_str[16];
            rtbh_get_ip_string(flow->src_ip);
            rtbh_get_ip_string(flow->dst_ip);
            printf("RTBH: Blocked traffic from %s to %s (packets: %u, bytes: %llu)\n", 
                   src_ip_str, dst_ip_str, 
                   flow->total_fwd_packets + flow->total_bwd_packets,
                   flow->total_fwd_bytes + flow->total_bwd_bytes);
        }
    }
    
    return 0;
}

int rtbh_should_blacklist_ip(rtbh_simulator_t *simulator, uint32_t ip_address, 
                             uint32_t packet_count, uint32_t byte_count) {
    if (!simulator) return 0;
    
    // Simple heuristic: blacklist if packet count exceeds threshold
    if (packet_count > simulator->config.threshold_packets) {
        return 1;
    }
    
    // Additional heuristics could be added here
    // - High packet rate
    // - Unusual traffic patterns
    // - Multiple failed connections
    
    return 0;
}

int rtbh_analyze_traffic_patterns(rtbh_simulator_t *simulator, time_window_t *window) {
    if (!simulator || !window) return -1;
    
    // Simple hash table for IP statistics
    #define HASH_SIZE 65536
    struct {
        uint32_t ip;
        uint32_t packet_count;
        uint32_t byte_count;
        uint32_t flow_count;
    } ip_stats[HASH_SIZE];
    
    memset(ip_stats, 0, sizeof(ip_stats));
    
    // Count packets per IP
    for (size_t i = 0; i < window->flow_count; i++) {
        uint32_t src_ip = window->flows[i].src_ip;
        uint32_t dst_ip = window->flows[i].dst_ip;
        uint32_t src_packets = window->flows[i].total_fwd_packets;
        uint32_t dst_packets = window->flows[i].total_bwd_packets;
        uint32_t src_bytes = window->flows[i].total_fwd_bytes;
        uint32_t dst_bytes = window->flows[i].total_bwd_bytes;
        
        // Process source IP
        uint32_t src_hash = src_ip % HASH_SIZE;
        if (ip_stats[src_hash].ip == 0 || ip_stats[src_hash].ip == src_ip) {
            ip_stats[src_hash].ip = src_ip;
            ip_stats[src_hash].packet_count += src_packets;
            ip_stats[src_hash].byte_count += src_bytes;
            ip_stats[src_hash].flow_count++;
        }
        
        // Process destination IP
        uint32_t dst_hash = dst_ip % HASH_SIZE;
        if (ip_stats[dst_hash].ip == 0 || ip_stats[dst_hash].ip == dst_ip) {
            ip_stats[dst_hash].ip = dst_ip;
            ip_stats[dst_hash].packet_count += dst_packets;
            ip_stats[dst_hash].byte_count += dst_bytes;
            ip_stats[dst_hash].flow_count++;
        }
    }
    
    // Check for suspicious IPs
    for (uint32_t i = 0; i < HASH_SIZE; i++) {
        if (ip_stats[i].ip != 0) {
            if (rtbh_should_blacklist_ip(simulator, ip_stats[i].ip, 
                                        ip_stats[i].packet_count, 
                                        ip_stats[i].byte_count)) {
                char reason[64];
                snprintf(reason, sizeof(reason), "High packet count: %u", ip_stats[i].packet_count);
                
                rtbh_add_to_blacklist(simulator, ip_stats[i].ip, 
                                     ip_stats[i].packet_count, 
                                     ip_stats[i].byte_count, reason);
            }
        }
    }
    
    return 0;
}

int rtbh_analyze_blocking_effectiveness(rtbh_simulator_t *simulator, time_window_t *window) {
    if (!simulator || !window) return -1;
    
    // Analysis is done in block_traffic function
    return 0;
}

void rtbh_print_statistics(rtbh_simulator_t *simulator) {
    printf("\n=== RTBH Simulator Statistics ===\n");
    printf("Configuration:\n");
    printf("  Max Blacklist Size: %u\n", simulator->config.max_blacklist_size);
    printf("  Blacklist Timeout: %llu ms\n", simulator->config.blacklist_timeout_ms);
    printf("  Packet Threshold: %.0f\n", simulator->config.threshold_packets);
    printf("  Logging Enabled: %s\n", simulator->config.enable_logging ? "Yes" : "No");
    
    printf("Current State:\n");
    printf("  Blacklist Entries: %u\n", simulator->blacklist_count);
    printf("  Total Blocked Packets: %u\n", simulator->total_blocked_packets);
    printf("  Total Blocked Bytes: %u\n", simulator->total_blocked_bytes);
    printf("  Total Blocked Flows: %u\n", simulator->total_blocked_flows);
    printf("  True Positives: %u\n", simulator->true_positives);
    printf("  False Positives: %u\n", simulator->false_positives);
    
    if (simulator->total_blocked_flows > 0) {
        printf("  Blocking Accuracy: %.2f%%\n", 
               (float)simulator->true_positives / simulator->total_blocked_flows * 100.0f);
    }
}

void rtbh_print_blacklist(rtbh_simulator_t *simulator) {
    if (!simulator) return;
    
    printf("\n=== RTBH Blacklist ===\n");
    printf("Entries: %u\n", simulator->blacklist_count);
    
    for (uint32_t i = 0; i < simulator->blacklist_count; i++) {
        blacklist_entry_t *entry = &simulator->blacklist[i];
        char ip_str[16];
        rtbh_get_ip_string(entry->ip_address);
        
        printf("  %s: packets=%u, bytes=%u, reason=%s\n", 
               ip_str, entry->packet_count, entry->byte_count, entry->reason);
    }
}

uint32_t rtbh_calculate_ip_score(uint32_t packet_count, uint32_t byte_count, 
                                uint32_t flow_count) {
    // Simple scoring function
    uint32_t score = packet_count + (byte_count / 1000) + (flow_count * 10);
    return score;
}

const char* rtbh_get_ip_string(uint32_t ip_address) {
    static char ip_str[16];
    sprintf(ip_str, "%d.%d.%d.%d", 
            (ip_address >> 24) & 0xFF, (ip_address >> 16) & 0xFF, 
            (ip_address >> 8) & 0xFF, ip_address & 0xFF);
    return ip_str;
}

void rtbh_set_config(rtbh_simulator_t *simulator, const rtbh_config_t *config) {
    if (simulator && config) {
        simulator->config = *config;
    }
}
