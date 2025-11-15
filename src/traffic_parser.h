#ifndef TRAFFIC_PARSER_H
#define TRAFFIC_PARSER_H

#include <stdint.h>
#include <time.h>

// Network flow structure based on CIC-DDoS2019 dataset
typedef struct {
    uint32_t src_ip;           // Source IP address
    uint32_t dst_ip;           // Destination IP address
    uint16_t src_port;         // Source port
    uint16_t dst_port;         // Destination port
    uint8_t protocol;          // Protocol (TCP=6, UDP=17, ICMP=1)
    uint64_t timestamp;        // Flow start time (microseconds)
    uint32_t flow_duration;    // Flow duration (microseconds)
    uint32_t total_fwd_packets; // Total forward packets
    uint32_t total_bwd_packets; // Total backward packets
    uint64_t total_fwd_bytes;   // Total forward bytes
    uint64_t total_bwd_bytes;   // Total backward bytes
    uint32_t fwd_packet_length_max; // Max forward packet length
    uint32_t fwd_packet_length_min; // Min forward packet length
    uint32_t fwd_packet_length_mean; // Mean forward packet length
    uint32_t fwd_packet_length_std;  // Std dev forward packet length
    uint32_t bwd_packet_length_max; // Max backward packet length
    uint32_t bwd_packet_length_min; // Min backward packet length
    uint32_t bwd_packet_length_mean; // Mean backward packet length
    uint32_t bwd_packet_length_std;  // Std dev backward packet length
    uint32_t flow_bytes_per_sec;     // Flow bytes per second
    uint32_t flow_packets_per_sec;   // Flow packets per second
    uint32_t flow_iat_mean;          // Flow inter-arrival time mean
    uint32_t flow_iat_std;           // Flow inter-arrival time std dev
    uint32_t flow_iat_max;           // Flow inter-arrival time max
    uint32_t flow_iat_min;           // Flow inter-arrival time min
    uint8_t fwd_iat_total;           // Forward IAT total
    uint8_t fwd_iat_mean;            // Forward IAT mean
    uint8_t fwd_iat_std;             // Forward IAT std dev
    uint8_t fwd_iat_max;             // Forward IAT max
    uint8_t fwd_iat_min;             // Forward IAT min
    uint8_t bwd_iat_total;           // Backward IAT total
    uint8_t bwd_iat_mean;            // Backward IAT mean
    uint8_t bwd_iat_std;             // Backward IAT std dev
    uint8_t bwd_iat_max;             // Backward IAT max
    uint8_t bwd_iat_min;             // Backward IAT min
    uint8_t fwd_psh_flags;           // Forward PSH flags
    uint8_t bwd_psh_flags;           // Backward PSH flags
    uint8_t fwd_urg_flags;           // Forward URG flags
    uint8_t bwd_urg_flags;           // Backward URG flags
    uint8_t fwd_header_length;      // Forward header length
    uint8_t bwd_header_length;      // Backward header length
    uint8_t fwd_packets_per_sec;     // Forward packets per second
    uint8_t bwd_packets_per_sec;     // Backward packets per second
    uint8_t min_packet_length;       // Min packet length
    uint8_t max_packet_length;       // Max packet length
    uint8_t packet_length_mean;      // Packet length mean
    uint8_t packet_length_std;       // Packet length std dev
    uint8_t packet_length_variance;  // Packet length variance
    uint8_t fin_flag_count;          // FIN flag count
    uint8_t syn_flag_count;          // SYN flag count
    uint8_t rst_flag_count;          // RST flag count
    uint8_t psh_flag_count;          // PSH flag count
    uint8_t ack_flag_count;          // ACK flag count
    uint8_t urg_flag_count;          // URG flag count
    uint8_t cwe_flag_count;          // CWE flag count
    uint8_t ece_flag_count;          // ECE flag count
    uint8_t down_up_ratio;           // Down/Up ratio
    uint8_t avg_packet_size;         // Average packet size
    uint8_t fwd_avg_bytes_per_bulk;  // Forward avg bytes per bulk
    uint8_t fwd_avg_packets_per_bulk; // Forward avg packets per bulk
    uint8_t fwd_avg_bulk_rate;       // Forward avg bulk rate
    uint8_t bwd_avg_bytes_per_bulk;  // Backward avg bytes per bulk
    uint8_t bwd_avg_packets_per_bulk; // Backward avg packets per bulk
    uint8_t bwd_avg_bulk_rate;       // Backward avg bulk rate
    uint8_t subflow_fwd_packets;      // Subflow forward packets
    uint8_t subflow_bwd_packets;     // Subflow backward packets
    uint8_t subflow_fwd_bytes;       // Subflow forward bytes
    uint8_t subflow_bwd_bytes;       // Subflow backward bytes
    uint8_t init_win_bytes_forward;  // Initial window bytes forward
    uint8_t init_win_bytes_backward; // Initial window bytes backward
    uint8_t act_data_pkt_fwd;        // Active data packets forward
    uint8_t min_seg_size_forward;    // Min segment size forward
    uint8_t active_mean;             // Active mean
    uint8_t active_std;              // Active std dev
    uint8_t active_max;              // Active max
    uint8_t active_min;              // Active min
    uint8_t idle_mean;               // Idle mean
    uint8_t idle_std;                // Idle std dev
    uint8_t idle_max;                // Idle max
    uint8_t idle_min;                // Idle min
    uint8_t label;                   // Attack label (0=Benign, 1=DDoS)
    uint8_t attack_type;             // Specific attack type
} network_flow_t;

// Flow collection structure
typedef struct {
    network_flow_t *flows;
    size_t count;
    size_t capacity;
    uint64_t start_time;
    uint64_t end_time;
} flow_collection_t;

// IP address statistics for entropy calculation
typedef struct ip_stats {
    uint32_t ip;
    uint32_t packet_count;
    uint32_t byte_count;
    uint64_t first_seen;
    uint64_t last_seen;
    struct ip_stats *next;  // For hash table chaining
} ip_stats_t;

// Time window for analysis
typedef struct {
    uint64_t start_time;
    uint64_t end_time;
    size_t flow_count;
    network_flow_t *flows;
} time_window_t;

// Function declarations
int parse_cic_ddos_csv(const char *filename, flow_collection_t *collection);
int parse_csv_line(const char *line, network_flow_t *flow);
void free_flow_collection(flow_collection_t *collection);
int create_time_windows(flow_collection_t *collection, time_window_t **windows, 
                        size_t *window_count, uint64_t window_size_ms);
void free_time_windows(time_window_t *windows, size_t count);

// IP statistics functions
int build_ip_statistics(flow_collection_t *collection, ip_stats_t **stats, 
                        size_t *stats_count);
void free_ip_statistics(ip_stats_t *stats);

// Utility functions
uint32_t ip_string_to_uint32(const char *ip_str);
void ip_uint32_to_string(uint32_t ip, char *ip_str);
uint64_t parse_timestamp(const char *timestamp_str);
int is_attack_flow(const network_flow_t *flow);
const char* get_attack_type_name(uint8_t attack_type);

// Data filtering functions
int filter_flows_by_time(flow_collection_t *collection, uint64_t start_time, 
                         uint64_t end_time, flow_collection_t *filtered);
int filter_flows_by_protocol(flow_collection_t *collection, uint8_t protocol, 
                             flow_collection_t *filtered);

#endif // TRAFFIC_PARSER_H
