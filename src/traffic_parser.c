#include "traffic_parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// CIC-DDoS2019 CSV column mapping
typedef enum {
    COL_SRC_IP = 0,
    COL_DST_IP = 1,
    COL_SRC_PORT = 2,
    COL_DST_PORT = 3,
    COL_PROTOCOL = 4,
    COL_TIMESTAMP = 5,
    COL_FLOW_DURATION = 6,
    COL_TOTAL_FWD_PACKETS = 7,
    COL_TOTAL_BWD_PACKETS = 8,
    COL_TOTAL_FWD_BYTES = 9,
    COL_TOTAL_BWD_BYTES = 10,
    COL_FWD_PACKET_LENGTH_MAX = 11,
    COL_FWD_PACKET_LENGTH_MIN = 12,
    COL_FWD_PACKET_LENGTH_MEAN = 13,
    COL_FWD_PACKET_LENGTH_STD = 14,
    COL_BWD_PACKET_LENGTH_MAX = 15,
    COL_BWD_PACKET_LENGTH_MIN = 16,
    COL_BWD_PACKET_LENGTH_MEAN = 17,
    COL_BWD_PACKET_LENGTH_STD = 18,
    COL_FLOW_BYTES_PER_SEC = 19,
    COL_FLOW_PACKETS_PER_SEC = 20,
    COL_FLOW_IAT_MEAN = 21,
    COL_FLOW_IAT_STD = 22,
    COL_FLOW_IAT_MAX = 23,
    COL_FLOW_IAT_MIN = 24,
    COL_FWD_IAT_TOTAL = 25,
    COL_FWD_IAT_MEAN = 26,
    COL_FWD_IAT_STD = 27,
    COL_FWD_IAT_MAX = 28,
    COL_FWD_IAT_MIN = 29,
    COL_BWD_IAT_TOTAL = 30,
    COL_BWD_IAT_MEAN = 31,
    COL_BWD_IAT_STD = 32,
    COL_BWD_IAT_MAX = 33,
    COL_BWD_IAT_MIN = 34,
    COL_FWD_PSH_FLAGS = 35,
    COL_BWD_PSH_FLAGS = 36,
    COL_FWD_URG_FLAGS = 37,
    COL_BWD_URG_FLAGS = 38,
    COL_FWD_HEADER_LENGTH = 39,
    COL_BWD_HEADER_LENGTH = 40,
    COL_FWD_PACKETS_PER_SEC = 41,
    COL_BWD_PACKETS_PER_SEC = 42,
    COL_MIN_PACKET_LENGTH = 43,
    COL_MAX_PACKET_LENGTH = 44,
    COL_PACKET_LENGTH_MEAN = 45,
    COL_PACKET_LENGTH_STD = 46,
    COL_PACKET_LENGTH_VARIANCE = 47,
    COL_FIN_FLAG_COUNT = 48,
    COL_SYN_FLAG_COUNT = 49,
    COL_RST_FLAG_COUNT = 50,
    COL_PSH_FLAG_COUNT = 51,
    COL_ACK_FLAG_COUNT = 52,
    COL_URG_FLAG_COUNT = 53,
    COL_CWE_FLAG_COUNT = 54,
    COL_ECE_FLAG_COUNT = 55,
    COL_DOWN_UP_RATIO = 56,
    COL_AVG_PACKET_SIZE = 57,
    COL_FWD_AVG_BYTES_PER_BULK = 58,
    COL_FWD_AVG_PACKETS_PER_BULK = 59,
    COL_FWD_AVG_BULK_RATE = 60,
    COL_BWD_AVG_BYTES_PER_BULK = 61,
    COL_BWD_AVG_PACKETS_PER_BULK = 62,
    COL_BWD_AVG_BULK_RATE = 63,
    COL_SUBFLOW_FWD_PACKETS = 64,
    COL_SUBFLOW_BWD_PACKETS = 65,
    COL_SUBFLOW_FWD_BYTES = 66,
    COL_SUBFLOW_BWD_BYTES = 67,
    COL_INIT_WIN_BYTES_FORWARD = 68,
    COL_INIT_WIN_BYTES_BACKWARD = 69,
    COL_ACT_DATA_PKT_FWD = 70,
    COL_MIN_SEG_SIZE_FORWARD = 71,
    COL_ACTIVE_MEAN = 72,
    COL_ACTIVE_STD = 73,
    COL_ACTIVE_MAX = 74,
    COL_ACTIVE_MIN = 75,
    COL_IDLE_MEAN = 76,
    COL_IDLE_STD = 77,
    COL_IDLE_MAX = 78,
    COL_IDLE_MIN = 79,
    COL_LABEL = 87,
    COL_COUNT = 88
} csv_column_t;

int parse_cic_ddos_csv(const char *filename, flow_collection_t *collection) {
    FILE *file;
    char line[4096];
    char *token;
    int line_count = 0;
    int parsed_count = 0;
    
    // Initialize collection
    collection->flows = NULL;
    collection->count = 0;
    collection->capacity = 0;
    collection->start_time = UINT64_MAX;
    collection->end_time = 0;
    
    file = fopen(filename, "r");
    if (!file) {
        fprintf(stderr, "Failed to open file: %s\n", filename);
        return -1;
    }
    
    // Skip header line
    if (fgets(line, sizeof(line), file) == NULL) {
        fprintf(stderr, "Empty file or no header\n");
        fclose(file);
        return -1;
    }
    line_count++;
    
    // Parse data lines
    while (fgets(line, sizeof(line), file) != NULL) {
        line_count++;
        
        // Remove newline
        line[strcspn(line, "\r\n")] = '\0';
        
        // Skip empty lines
        if (strlen(line) == 0) continue;
        
        // Expand collection if needed
        if (collection->count >= collection->capacity) {
            collection->capacity = collection->capacity == 0 ? 1000 : collection->capacity * 2;
            collection->flows = (network_flow_t*)realloc(collection->flows, 
                                                         collection->capacity * sizeof(network_flow_t));
            if (!collection->flows) {
                fprintf(stderr, "Memory allocation failed\n");
                fclose(file);
                return -1;
            }
        }
        
        // Parse the line
        if (parse_csv_line(line, &collection->flows[collection->count]) == 0) {
            // Update time bounds
            if (collection->flows[collection->count].timestamp < collection->start_time) {
                collection->start_time = collection->flows[collection->count].timestamp;
            }
            if (collection->flows[collection->count].timestamp > collection->end_time) {
                collection->end_time = collection->flows[collection->count].timestamp;
            }
            
            collection->count++;
            parsed_count++;
        } else {
            fprintf(stderr, "Failed to parse line %d: %s\n", line_count, line);
        }
        
        // Progress indicator
        if (line_count % 10000 == 0) {
            printf("Parsed %d lines, %d flows loaded...\r", line_count, parsed_count);
            fflush(stdout);
        }
    }
    
    fclose(file);
    printf("\nParsed %d flows from %d lines\n", parsed_count, line_count);
    return 0;
}

int parse_csv_line(const char *line, network_flow_t *flow) {
    char line_copy[4096];
    char *token;
    int col = 0;
    double temp_val;
    
    strcpy(line_copy, line);
    
    // Initialize flow
    memset(flow, 0, sizeof(network_flow_t));
    
    token = strtok(line_copy, ",");
    while (token != NULL && col < COL_COUNT) {
        // Skip whitespace
        while (*token == ' ' || *token == '\t') token++;
        
        switch (col) {
            case COL_SRC_IP:
                flow->src_ip = ip_string_to_uint32(token);
                break;
            case COL_DST_IP:
                flow->dst_ip = ip_string_to_uint32(token);
                break;
            case COL_SRC_PORT:
                flow->src_port = (uint16_t)strtoul(token, NULL, 10);
                break;
            case COL_DST_PORT:
                flow->dst_port = (uint16_t)strtoul(token, NULL, 10);
                break;
            case COL_PROTOCOL:
                flow->protocol = (uint8_t)strtoul(token, NULL, 10);
                break;
            case COL_TIMESTAMP:
                flow->timestamp = parse_timestamp(token);
                break;
            case COL_FLOW_DURATION:
                flow->flow_duration = (uint32_t)strtoul(token, NULL, 10);
                break;
            case COL_TOTAL_FWD_PACKETS:
                flow->total_fwd_packets = (uint32_t)strtoul(token, NULL, 10);
                break;
            case COL_TOTAL_BWD_PACKETS:
                flow->total_bwd_packets = (uint32_t)strtoul(token, NULL, 10);
                break;
            case COL_TOTAL_FWD_BYTES:
                flow->total_fwd_bytes = (uint64_t)strtoull(token, NULL, 10);
                break;
            case COL_TOTAL_BWD_BYTES:
                flow->total_bwd_bytes = (uint64_t)strtoull(token, NULL, 10);
                break;
            case COL_FLOW_BYTES_PER_SEC:
                flow->flow_bytes_per_sec = (uint32_t)strtoul(token, NULL, 10);
                break;
            case COL_FLOW_PACKETS_PER_SEC:
                flow->flow_packets_per_sec = (uint32_t)strtoul(token, NULL, 10);
                break;
            case COL_LABEL:
                // Parse string label to numeric value
                if (strcmp(token, "BENIGN") == 0) {
                    flow->label = 0;  // Benign
                } else if (strstr(token, "DrDoS") != NULL || 
                          strstr(token, "DDoS") != NULL ||
                          strstr(token, "Syn") != NULL ||
                          strstr(token, "TFTP") != NULL) {
                    flow->label = 1;  // Attack
                } else {
                    flow->label = 0;  // Default to benign for unknown labels
                }
                break;
            default:
                // For other columns, try to parse as numeric
                temp_val = strtod(token, NULL);
                if (temp_val < 0) temp_val = 0;
                if (temp_val > 255) temp_val = 255;
                // Store in appropriate field based on column
                break;
        }
        
        col++;
        token = strtok(NULL, ",");
    }
    
    return (col >= COL_COUNT) ? 0 : -1;
}

void free_flow_collection(flow_collection_t *collection) {
    if (collection->flows) {
        free(collection->flows);
        collection->flows = NULL;
    }
    collection->count = 0;
    collection->capacity = 0;
}

int create_time_windows(flow_collection_t *collection, time_window_t **windows, 
                        size_t *window_count, uint64_t window_size_ms) {
    uint64_t duration = collection->end_time - collection->start_time;
    *window_count = (duration / window_size_ms) + 1;
    
    *windows = (time_window_t*)calloc(*window_count, sizeof(time_window_t));
    if (!*windows) {
        fprintf(stderr, "Memory allocation failed for time windows\n");
        return -1;
    }
    
    // Initialize windows
    for (size_t i = 0; i < *window_count; i++) {
        (*windows)[i].start_time = collection->start_time + (i * window_size_ms * 1000);
        (*windows)[i].end_time = (*windows)[i].start_time + (window_size_ms * 1000);
        (*windows)[i].flow_count = 0;
        (*windows)[i].flows = NULL;
    }
    
    // Distribute flows to windows
    for (size_t i = 0; i < collection->count; i++) {
        uint64_t flow_time = collection->flows[i].timestamp;
        size_t window_idx = (flow_time - collection->start_time) / (window_size_ms * 1000);
        
        if (window_idx < *window_count) {
            (*windows)[window_idx].flow_count++;
        }
    }
    
    // Allocate flow arrays for each window
    for (size_t i = 0; i < *window_count; i++) {
        if ((*windows)[i].flow_count > 0) {
            (*windows)[i].flows = (network_flow_t*)malloc(
                (*windows)[i].flow_count * sizeof(network_flow_t));
            if (!(*windows)[i].flows) {
                fprintf(stderr, "Memory allocation failed for window %zu\n", i);
                free_time_windows(*windows, *window_count);
                return -1;
            }
            (*windows)[i].flow_count = 0; // Reset for filling
        }
    }
    
    // Fill windows with flows
    for (size_t i = 0; i < collection->count; i++) {
        uint64_t flow_time = collection->flows[i].timestamp;
        size_t window_idx = (flow_time - collection->start_time) / (window_size_ms * 1000);
        
        if (window_idx < *window_count) {
            size_t flow_idx = (*windows)[window_idx].flow_count;
            (*windows)[window_idx].flows[flow_idx] = collection->flows[i];
            (*windows)[window_idx].flow_count++;
        }
    }
    
    return 0;
}

void free_time_windows(time_window_t *windows, size_t count) {
    for (size_t i = 0; i < count; i++) {
        if (windows[i].flows) {
            free(windows[i].flows);
        }
    }
    free(windows);
}

int build_ip_statistics(flow_collection_t *collection, ip_stats_t **stats, 
                        size_t *stats_count) {
    // Simple hash table implementation for IP statistics
    #define HASH_TABLE_SIZE 65536
    ip_stats_t *hash_table[HASH_TABLE_SIZE];
    memset(hash_table, 0, sizeof(hash_table));
    
    *stats_count = 0;
    
    // Count unique IPs
    for (size_t i = 0; i < collection->count; i++) {
        uint32_t src_ip = collection->flows[i].src_ip;
        uint32_t dst_ip = collection->flows[i].dst_ip;
        
        // Process source IP
        uint32_t hash = src_ip % HASH_TABLE_SIZE;
        ip_stats_t *current = hash_table[hash];
        while (current && current->ip != src_ip) {
            current = current->next;
        }
        if (!current) {
            current = (ip_stats_t*)malloc(sizeof(ip_stats_t));
            current->ip = src_ip;
            current->packet_count = 0;
            current->byte_count = 0;
            current->first_seen = collection->flows[i].timestamp;
            current->last_seen = collection->flows[i].timestamp;
            current->next = hash_table[hash];
            hash_table[hash] = current;
            (*stats_count)++;
        }
        current->packet_count += collection->flows[i].total_fwd_packets;
        current->byte_count += collection->flows[i].total_fwd_bytes;
        if (collection->flows[i].timestamp < current->first_seen) {
            current->first_seen = collection->flows[i].timestamp;
        }
        if (collection->flows[i].timestamp > current->last_seen) {
            current->last_seen = collection->flows[i].timestamp;
        }
        
        // Process destination IP
        hash = dst_ip % HASH_TABLE_SIZE;
        current = hash_table[hash];
        while (current && current->ip != dst_ip) {
            current = current->next;
        }
        if (!current) {
            current = (ip_stats_t*)malloc(sizeof(ip_stats_t));
            current->ip = dst_ip;
            current->packet_count = 0;
            current->byte_count = 0;
            current->first_seen = collection->flows[i].timestamp;
            current->last_seen = collection->flows[i].timestamp;
            current->next = hash_table[hash];
            hash_table[hash] = current;
            (*stats_count)++;
        }
        current->packet_count += collection->flows[i].total_bwd_packets;
        current->byte_count += collection->flows[i].total_bwd_bytes;
        if (collection->flows[i].timestamp < current->first_seen) {
            current->first_seen = collection->flows[i].timestamp;
        }
        if (collection->flows[i].timestamp > current->last_seen) {
            current->last_seen = collection->flows[i].timestamp;
        }
    }
    
    // Convert hash table to array
    *stats = (ip_stats_t*)malloc(*stats_count * sizeof(ip_stats_t));
    size_t idx = 0;
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        ip_stats_t *current = hash_table[i];
        while (current) {
            (*stats)[idx++] = *current;
            ip_stats_t *next = current->next;
            free(current);
            current = next;
        }
    }
    
    return 0;
}

void free_ip_statistics(ip_stats_t *stats) {
    free(stats);
}

uint32_t ip_string_to_uint32(const char *ip_str) {
    uint32_t ip = 0;
    int octets[4];
    
    if (sscanf(ip_str, "%d.%d.%d.%d", &octets[0], &octets[1], &octets[2], &octets[3]) == 4) {
        ip = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
    }
    
    return ip;
}

void ip_uint32_to_string(uint32_t ip, char *ip_str) {
    sprintf(ip_str, "%d.%d.%d.%d", 
            (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, 
            (ip >> 8) & 0xFF, ip & 0xFF);
}

uint64_t parse_timestamp(const char *timestamp_str) {
    // CIC-DDoS2019 uses format: DD/MM/YYYY HH:MM:SS.microseconds
    struct tm tm;
    uint64_t microseconds;
    
    if (sscanf(timestamp_str, "%d/%d/%d %d:%d:%d.%llu", 
               &tm.tm_mday, &tm.tm_mon, &tm.tm_year,
               &tm.tm_hour, &tm.tm_min, &tm.tm_sec, &microseconds) == 7) {
        tm.tm_year -= 1900; // Adjust year
        tm.tm_mon -= 1;     // Adjust month (0-based)
        
        time_t time_val = mktime(&tm);
        return (uint64_t)time_val * 1000000 + microseconds;
    }
    
    return 0;
}

int is_attack_flow(const network_flow_t *flow) {
    return flow->label == 1;
}

const char* get_attack_type_name(uint8_t attack_type) {
    switch (attack_type) {
        case 0: return "BENIGN";
        case 1: return "DDoS";
        default: return "UNKNOWN";
    }
}

int filter_flows_by_time(flow_collection_t *collection, uint64_t start_time, 
                         uint64_t end_time, flow_collection_t *filtered) {
    filtered->flows = NULL;
    filtered->count = 0;
    filtered->capacity = 0;
    
    // Count matching flows
    for (size_t i = 0; i < collection->count; i++) {
        if (collection->flows[i].timestamp >= start_time && 
            collection->flows[i].timestamp <= end_time) {
            filtered->count++;
        }
    }
    
    if (filtered->count == 0) return 0;
    
    // Allocate and copy flows
    filtered->flows = (network_flow_t*)malloc(filtered->count * sizeof(network_flow_t));
    if (!filtered->flows) return -1;
    
    size_t idx = 0;
    for (size_t i = 0; i < collection->count; i++) {
        if (collection->flows[i].timestamp >= start_time && 
            collection->flows[i].timestamp <= end_time) {
            filtered->flows[idx++] = collection->flows[i];
        }
    }
    
    return 0;
}

int filter_flows_by_protocol(flow_collection_t *collection, uint8_t protocol, 
                             flow_collection_t *filtered) {
    filtered->flows = NULL;
    filtered->count = 0;
    filtered->capacity = 0;
    
    // Count matching flows
    for (size_t i = 0; i < collection->count; i++) {
        if (collection->flows[i].protocol == protocol) {
            filtered->count++;
        }
    }
    
    if (filtered->count == 0) return 0;
    
    // Allocate and copy flows
    filtered->flows = (network_flow_t*)malloc(filtered->count * sizeof(network_flow_t));
    if (!filtered->flows) return -1;
    
    size_t idx = 0;
    for (size_t i = 0; i < collection->count; i++) {
        if (collection->flows[i].protocol == protocol) {
            filtered->flows[idx++] = collection->flows[i];
        }
    }
    
    return 0;
}
