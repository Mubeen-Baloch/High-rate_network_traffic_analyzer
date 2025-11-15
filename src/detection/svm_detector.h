#ifndef SVM_DETECTOR_H
#define SVM_DETECTOR_H

#include "traffic_parser.h"
#include "opencl_manager.h"
#include "metrics.h"

// SVM model structure
typedef struct {
    float *weights;              // Support vector weights
    float *support_vectors;      // Support vectors
    float bias;                  // SVM bias
    uint32_t num_support_vectors; // Number of support vectors
    uint32_t num_features;       // Number of features
    float gamma;                 // RBF kernel parameter
    float *feature_means;        // Feature normalization means
    float *feature_stds;         // Feature normalization std devs
    int trained;                 // Model training status
} svm_model_t;

// SVM detection configuration
typedef struct {
    float gamma;                 // RBF kernel parameter
    float c_parameter;          // SVM C parameter
    uint32_t max_iterations;    // Maximum training iterations
    float convergence_threshold; // Convergence threshold
    int use_gpu;                // Use GPU for inference
} svm_config_t;

// SVM detector state
typedef struct {
    svm_config_t config;
    svm_model_t model;
    opencl_context_t *opencl_ctx;
    
    // GPU buffers
    opencl_buffer_t feature_buffer;
    opencl_buffer_t weight_buffer;
    opencl_buffer_t support_vector_buffer;
    opencl_buffer_t bias_buffer;
    opencl_buffer_t prediction_buffer;
    opencl_buffer_t normalization_buffer;
    
    // CPU arrays
    float *features;
    float *predictions;
    float *normalized_features;
    
    // Feature extraction
    uint32_t num_features;
    uint32_t max_samples;
    
    // Metrics
    algorithm_metrics_t *metrics;
} svm_detector_t;

// Function declarations
int svm_detector_init(svm_detector_t *detector, opencl_context_t *opencl_ctx, 
                     const svm_config_t *config, algorithm_metrics_t *metrics);
void svm_detector_cleanup(svm_detector_t *detector);

// Training functions
int svm_detector_train(svm_detector_t *detector, flow_collection_t *training_data);
int svm_detector_load_model(svm_detector_t *detector, const char *model_file);
int svm_detector_save_model(svm_detector_t *detector, const char *model_file);

// Detection functions
int svm_detector_process_flows(svm_detector_t *detector, flow_collection_t *flows);
int svm_detector_process_window(svm_detector_t *detector, time_window_t *window);

// Feature extraction functions
int svm_detector_extract_features(svm_detector_t *detector, time_window_t *window);
int svm_detector_extract_features_batch(svm_detector_t *detector, time_window_t *window, 
                                        size_t batch_start, size_t batch_size);
int svm_detector_extract_features_gpu(svm_detector_t *detector, time_window_t *window);
int svm_detector_extract_features_cpu(svm_detector_t *detector, time_window_t *window);

// SVM inference functions
int svm_detector_inference(svm_detector_t *detector, float *features, uint32_t num_samples);
int svm_detector_inference_gpu(svm_detector_t *detector, float *features, uint32_t num_samples);
int svm_detector_inference_cpu(svm_detector_t *detector, float *features, uint32_t num_samples);

// Utility functions
void svm_detector_get_default_config(svm_config_t *config);
void svm_detector_set_config(svm_detector_t *detector, const svm_config_t *config);
int svm_detector_normalize_features(svm_detector_t *detector, float *features, uint32_t num_samples);

// Analysis functions
int svm_detector_analyze_results(svm_detector_t *detector, time_window_t *window, 
                                float *predictions);
void svm_detector_print_statistics(svm_detector_t *detector);

// Model management
int svm_model_init(svm_model_t *model, uint32_t num_features);
void svm_model_cleanup(svm_model_t *model);
int svm_model_allocate(svm_model_t *model, uint32_t num_support_vectors);

#endif // SVM_DETECTOR_H
