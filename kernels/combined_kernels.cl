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
// OpenCL kernels for SVM-based DDoS detection
// Feature extraction and SVM inference kernels

// Kernel for extracting features from network flows
__kernel void extract_features(
    __global float* flow_data,        // Input flow data (packed)
    __global float* features,         // Output feature vector
    uint num_flows,                   // Number of flows
    uint features_per_flow            // Number of features per flow
) {
    uint gid = get_global_id(0);
    
    if (gid >= num_flows) return;
    
    uint offset = gid * features_per_flow;
    
    // Extract features from flow data
    // Features: packet_rate, byte_rate, flow_duration, packet_size_mean, 
    //           packet_size_std, protocol_distribution, port_distribution
    
    // Packet rate (packets per second)
    float total_packets = flow_data[offset + 0] + flow_data[offset + 1]; // fwd + bwd packets
    float flow_duration = flow_data[offset + 2]; // duration in seconds
    float packet_rate = (flow_duration > 0) ? total_packets / flow_duration : 0.0f;
    
    // Byte rate (bytes per second)
    float total_bytes = flow_data[offset + 3] + flow_data[offset + 4]; // fwd + bwd bytes
    float byte_rate = (flow_duration > 0) ? total_bytes / flow_duration : 0.0f;
    
    // Packet size mean
    float packet_size_mean = (total_packets > 0) ? total_bytes / total_packets : 0.0f;
    
    // Packet size variance (simplified)
    float packet_size_var = flow_data[offset + 5]; // pre-calculated variance
    
    // Protocol distribution (normalized)
    float protocol = flow_data[offset + 6]; // protocol type
    
    // Port distribution (normalized)
    float src_port = flow_data[offset + 7];
    float dst_port = flow_data[offset + 8];
    
    // Store extracted features
    features[offset + 0] = packet_rate;
    features[offset + 1] = byte_rate;
    features[offset + 2] = flow_duration;
    features[offset + 3] = packet_size_mean;
    features[offset + 4] = packet_size_var;
    features[offset + 5] = protocol / 255.0f; // Normalize protocol
    features[offset + 6] = src_port / 65535.0f; // Normalize port
    features[offset + 7] = dst_port / 65535.0f; // Normalize port
}

// Kernel for SVM inference using RBF kernel
__kernel void svm_inference(
    __global float* features,         // Input feature vectors
    __global float* svm_weights,      // SVM model weights
    __global float* svm_support_vectors, // Support vectors
    __global float* svm_bias,          // SVM bias
    __global float* predictions,       // Output predictions
    uint num_samples,                  // Number of samples
    uint num_features,                 // Number of features per sample
    uint num_support_vectors,          // Number of support vectors
    float gamma                        // RBF kernel parameter
) {
    uint gid = get_global_id(0);
    
    if (gid >= num_samples) return;
    
    float prediction = 0.0f;
    
    // Calculate SVM decision function
    for (uint i = 0; i < num_support_vectors; i++) {
        float kernel_value = 0.0f;
        
        // Calculate RBF kernel: K(x, x') = exp(-gamma * ||x - x'||^2)
        for (uint j = 0; j < num_features; j++) {
            float diff = features[gid * num_features + j] - 
                        svm_support_vectors[i * num_features + j];
            kernel_value += diff * diff;
        }
        
        kernel_value = exp(-gamma * kernel_value);
        
        // Add weighted kernel value
        prediction += svm_weights[i] * kernel_value;
    }
    
    // Add bias
    prediction += svm_bias[0];
    
    // Apply sign function for binary classification
    predictions[gid] = (prediction > 0.0f) ? 1.0f : 0.0f;
}

// Kernel for parallel feature normalization
__kernel void normalize_features(
    __global float* features,         // Input/output features
    __global float* feature_means,    // Feature means
    __global float* feature_stds,     // Feature standard deviations
    uint num_samples,                  // Number of samples
    uint num_features                  // Number of features
) {
    uint gid = get_global_id(0);
    uint feature_idx = gid % num_features;
    uint sample_idx = gid / num_features;
    
    if (sample_idx >= num_samples || feature_idx >= num_features) return;
    
    uint offset = sample_idx * num_features + feature_idx;
    
    // Normalize: (x - mean) / std
    float normalized = (features[offset] - feature_means[feature_idx]) / feature_stds[feature_idx];
    features[offset] = normalized;
}

// Kernel for batch feature extraction from time windows
__kernel void extract_window_features(
    __global uint* src_ips,           // Source IPs
    __global uint* dst_ips,          // Destination IPs
    __global uint* src_ports,         // Source ports
    __global uint* dst_ports,        // Destination ports
    __global uint* protocols,        // Protocols
    __global uint* packet_counts,    // Packet counts
    __global uint* byte_counts,      // Byte counts
    __global uint* durations,        // Flow durations
    __global float* window_features, // Output window-level features
    uint num_flows,                   // Number of flows in window
    uint window_duration_ms           // Window duration in milliseconds
) {
    uint gid = get_global_id(0);
    
    if (gid != 0) return; // Only one work item needed for window-level features
    
    // Calculate window-level statistics
    uint total_packets = 0;
    uint total_bytes = 0;
    float total_duration = 0.0f;
    uint unique_src_ips = 0;
    uint unique_dst_ips = 0;
    uint unique_ports = 0;
    
    // Simple hash-based unique counting (simplified)
    uint src_ip_hash[256] = {0};
    uint dst_ip_hash[256] = {0};
    uint port_hash[256] = {0};
    
    for (uint i = 0; i < num_flows; i++) {
        total_packets += packet_counts[i];
        total_bytes += byte_counts[i];
        total_duration += (float)durations[i];
        
        // Count unique values (simplified hashing)
        src_ip_hash[src_ips[i] % 256] = 1;
        dst_ip_hash[dst_ips[i] % 256] = 1;
        port_hash[src_ports[i] % 256] = 1;
        port_hash[dst_ports[i] % 256] = 1;
    }
    
    // Count unique values
    for (uint i = 0; i < 256; i++) {
        if (src_ip_hash[i]) unique_src_ips++;
        if (dst_ip_hash[i]) unique_dst_ips++;
        if (port_hash[i]) unique_ports++;
    }
    
    // Calculate features
    float window_duration_sec = (float)window_duration_ms / 1000.0f;
    
    window_features[0] = (window_duration_sec > 0) ? (float)total_packets / window_duration_sec : 0.0f; // Packet rate
    window_features[1] = (window_duration_sec > 0) ? (float)total_bytes / window_duration_sec : 0.0f; // Byte rate
    window_features[2] = (float)unique_src_ips / (float)num_flows; // Source IP diversity
    window_features[3] = (float)unique_dst_ips / (float)num_flows; // Destination IP diversity
    window_features[4] = (float)unique_ports / (float)num_flows; // Port diversity
    window_features[5] = (total_packets > 0) ? (float)total_bytes / (float)total_packets : 0.0f; // Avg packet size
    window_features[6] = (float)num_flows / window_duration_sec; // Flow rate
}

// Kernel for calculating feature importance scores
__kernel void calculate_feature_importance(
    __global float* features,         // Input features
    __global float* labels,          // True labels
    __global float* importance_scores, // Output importance scores
    uint num_samples,                 // Number of samples
    uint num_features                 // Number of features
) {
    uint feature_idx = get_global_id(0);
    
    if (feature_idx >= num_features) return;
    
    // Calculate correlation between feature and labels
    float sum_feature = 0.0f;
    float sum_label = 0.0f;
    float sum_feature_squared = 0.0f;
    float sum_label_squared = 0.0f;
    float sum_feature_label = 0.0f;
    
    for (uint i = 0; i < num_samples; i++) {
        float feature_val = features[i * num_features + feature_idx];
        float label_val = labels[i];
        
        sum_feature += feature_val;
        sum_label += label_val;
        sum_feature_squared += feature_val * feature_val;
        sum_label_squared += label_val * label_val;
        sum_feature_label += feature_val * label_val;
    }
    
    // Calculate correlation coefficient
    float n = (float)num_samples;
    float numerator = n * sum_feature_label - sum_feature * sum_label;
    float denominator = sqrt((n * sum_feature_squared - sum_feature * sum_feature) * 
                           (n * sum_label_squared - sum_label * sum_label));
    
    float correlation = (denominator > 0) ? numerator / denominator : 0.0f;
    
    // Store absolute correlation as importance score
    importance_scores[feature_idx] = fabs(correlation);
}
