// OpenCL kernel for entropy-based DDoS detection
// This kernel calculates Shannon entropy of destination IP addresses
// Low entropy indicates DDoS attack (many packets to few targets)

__kernel void calculate_entropy(
    __global uint* ip_addresses,      // Array of destination IP addresses
    __global uint* packet_counts,     // Packet count per IP
    __global float* entropy_results,  // Output entropy values
    uint window_size                  // Number of IPs in current window
) {
    uint gid = get_global_id(0);
    
    if (gid >= window_size) return;
    
    // Calculate total packets in window
    uint total_packets = 0;
    for (uint i = 0; i < window_size; i++) {
        total_packets += packet_counts[i];
    }
    
    if (total_packets == 0) {
        entropy_results[gid] = 0.0f;
        return;
    }
    
    // Calculate Shannon entropy: H = -sum(p_i * log2(p_i))
    float entropy = 0.0f;
    for (uint i = 0; i < window_size; i++) {
        if (packet_counts[i] > 0) {
            float probability = (float)packet_counts[i] / (float)total_packets;
            entropy -= probability * log2(probability);
        }
    }
    
    entropy_results[gid] = entropy;
}

// Kernel for parallel IP counting and aggregation
__kernel void aggregate_ip_counts(
    __global uint* src_ips,          // Source IP addresses
    __global uint* dst_ips,          // Destination IP addresses  
    __global uint* packet_counts,     // Packet counts per flow
    __global uint* ip_counts,         // Output: aggregated counts per unique IP
    __global uint* unique_ips,        // Output: unique IP addresses
    uint num_flows,                   // Number of flows to process
    uint max_unique_ips              // Maximum number of unique IPs
) {
    uint gid = get_global_id(0);
    
    if (gid >= num_flows) return;
    
    uint src_ip = src_ips[gid];
    uint dst_ip = dst_ips[gid];
    uint packet_count = packet_counts[gid];
    
    // Simple hash-based aggregation
    uint src_hash = src_ip % max_unique_ips;
    uint dst_hash = dst_ip % max_unique_ips;
    
    // Atomic operations for thread-safe updates
    atomic_add(&ip_counts[src_hash], packet_count);
    atomic_add(&ip_counts[dst_hash], packet_count);
    
    // Store unique IPs (simplified - may have collisions)
    unique_ips[src_hash] = src_ip;
    unique_ips[dst_hash] = dst_ip;
}

// Kernel for calculating entropy-based detection threshold
__kernel void calculate_entropy_threshold(
    __global float* entropy_values,   // Input entropy values
    __global float* threshold,        // Output threshold
    uint num_values,                  // Number of entropy values
    float sensitivity                 // Detection sensitivity (0.0-1.0)
) {
    uint gid = get_global_id(0);
    
    if (gid != 0) return; // Only one work item needed
    
    // Calculate mean entropy
    float sum = 0.0f;
    for (uint i = 0; i < num_values; i++) {
        sum += entropy_values[i];
    }
    float mean_entropy = sum / (float)num_values;
    
    // Calculate standard deviation
    float variance = 0.0f;
    for (uint i = 0; i < num_values; i++) {
        float diff = entropy_values[i] - mean_entropy;
        variance += diff * diff;
    }
    float std_dev = sqrt(variance / (float)num_values);
    
    // Set threshold based on sensitivity
    // Lower threshold = more sensitive detection
    threshold[0] = mean_entropy - (sensitivity * std_dev);
}

// Kernel for detecting low entropy (potential DDoS)
__kernel void detect_low_entropy(
    __global float* entropy_values,   // Input entropy values
    __global float* threshold,        // Detection threshold
    __global uint* detection_results, // Output: 1 if attack detected, 0 otherwise
    uint num_values                   // Number of entropy values to check
) {
    uint gid = get_global_id(0);
    
    if (gid >= num_values) return;
    
    // Detect if entropy is below threshold
    if (entropy_values[gid] < threshold[0]) {
        detection_results[gid] = 1; // Attack detected
    } else {
        detection_results[gid] = 0; // Normal traffic
    }
}

// Utility kernel for data preprocessing
__kernel void preprocess_flow_data(
    __global uint* src_ips,          // Source IPs
    __global uint* dst_ips,          // Destination IPs
    __global uint* src_ports,        // Source ports
    __global uint* dst_ports,        // Destination ports
    __global uint* protocols,        // Protocols
    __global uint* packet_counts,    // Packet counts
    __global uint* byte_counts,      // Byte counts
    __global uint* timestamps,       // Timestamps
    __global uint* processed_data,   // Output processed data
    uint num_flows,                  // Number of flows
    uint window_start_time,          // Window start time
    uint window_end_time             // Window end time
) {
    uint gid = get_global_id(0);
    
    if (gid >= num_flows) return;
    
    // Filter flows within time window
    uint timestamp = timestamps[gid];
    if (timestamp >= window_start_time && timestamp <= window_end_time) {
        // Pack data into output array (simplified)
        uint offset = gid * 7; // 7 fields per flow
        processed_data[offset + 0] = src_ips[gid];
        processed_data[offset + 1] = dst_ips[gid];
        processed_data[offset + 2] = src_ports[gid];
        processed_data[offset + 3] = dst_ports[gid];
        processed_data[offset + 4] = protocols[gid];
        processed_data[offset + 5] = packet_counts[gid];
        processed_data[offset + 6] = byte_counts[gid];
    }
}
