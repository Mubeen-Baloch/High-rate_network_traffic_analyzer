#ifndef OPENCL_MANAGER_H
#define OPENCL_MANAGER_H

#include <CL/cl.h>
#include <stdint.h>

// OpenCL context and device management
typedef struct {
    cl_platform_id platform;
    cl_device_id device;
    cl_context context;
    cl_command_queue command_queue;
    cl_program program;
    cl_kernel entropy_kernel;
    cl_kernel feature_extraction_kernel;
    cl_kernel svm_inference_kernel;
    int device_count;
    int initialized;
} opencl_context_t;

// OpenCL buffer management
typedef struct {
    cl_mem buffer;
    size_t size;
    cl_mem_flags flags;
} opencl_buffer_t;

// Function declarations
int opencl_init(opencl_context_t *ctx);
void opencl_cleanup(opencl_context_t *ctx);
int opencl_load_kernels(opencl_context_t *ctx, const char *kernel_path);
int opencl_create_buffer(opencl_context_t *ctx, opencl_buffer_t *buf, 
                         size_t size, cl_mem_flags flags);
int opencl_write_buffer(opencl_context_t *ctx, opencl_buffer_t *buf, 
                        const void *data, size_t size);
int opencl_read_buffer(opencl_context_t *ctx, opencl_buffer_t *buf, 
                       void *data, size_t size);
void opencl_release_buffer(opencl_buffer_t *buf);

// Kernel execution helpers
int opencl_execute_entropy_kernel(opencl_context_t *ctx, 
                                  opencl_buffer_t *ip_data,
                                  opencl_buffer_t *packet_counts,
                                  opencl_buffer_t *entropy_results,
                                  size_t num_ips, size_t window_size);

int opencl_execute_feature_extraction_kernel(opencl_context_t *ctx,
                                            opencl_buffer_t *flow_data,
                                            opencl_buffer_t *features,
                                            size_t num_flows);

int opencl_execute_svm_kernel(opencl_context_t *ctx,
                             opencl_buffer_t *features,
                             opencl_buffer_t *svm_weights,
                             opencl_buffer_t *svm_support_vectors,
                             opencl_buffer_t *svm_bias,
                             opencl_buffer_t *predictions,
                             unsigned int num_samples, unsigned int num_features, 
                             unsigned int num_support_vectors, float gamma);

// Utility functions
const char* opencl_get_error_string(cl_int error);
void opencl_print_device_info(cl_device_id device);

// Optional: Query hardware GPU utilization via NVML if available (guarded by USE_NVML)
// Returns 0 on success and writes utilization_percent (0-100), otherwise returns -1
int opencl_query_gpu_utilization(opencl_context_t *ctx, float *utilization_percent);

#endif // OPENCL_MANAGER_H
