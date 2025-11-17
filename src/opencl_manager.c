#include "opencl_manager.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

// OpenCL error checking macro
#define CHECK_OPENCL_ERROR(err, msg) \
    do { \
        if (err != CL_SUCCESS) { \
            fprintf(stderr, "OpenCL Error: %s (%s)\n", msg, opencl_get_error_string(err)); \
            return -1; \
        } \
    } while(0)

int opencl_init(opencl_context_t *ctx) {
    cl_int err;
    
    // Initialize context structure
    memset(ctx, 0, sizeof(opencl_context_t));
    
    // Get platform
    err = clGetPlatformIDs(1, &ctx->platform, NULL);
    CHECK_OPENCL_ERROR(err, "Failed to get platform");
    
    // Get device (prefer NVIDIA GPU)
    err = clGetDeviceIDs(ctx->platform, CL_DEVICE_TYPE_GPU, 1, &ctx->device, 
                         (cl_uint*)&ctx->device_count);
    if (err != CL_SUCCESS) {
        fprintf(stderr, "No GPU found, trying CPU...\n");
        err = clGetDeviceIDs(ctx->platform, CL_DEVICE_TYPE_CPU, 1, &ctx->device, 
                             (cl_uint*)&ctx->device_count);
    }
    CHECK_OPENCL_ERROR(err, "Failed to get device");
    
    // Print device info
    opencl_print_device_info(ctx->device);
    
    // Create context
    ctx->context = clCreateContext(NULL, 1, &ctx->device, NULL, NULL, &err);
    CHECK_OPENCL_ERROR(err, "Failed to create context");
    
    // Create command queue
    ctx->command_queue = clCreateCommandQueue(ctx->context, ctx->device, 
                                             CL_QUEUE_PROFILING_ENABLE, &err);
    CHECK_OPENCL_ERROR(err, "Failed to create command queue");
    
    ctx->initialized = 1;
    printf("OpenCL initialized successfully\n");
    return 0;
}

void opencl_cleanup(opencl_context_t *ctx) {
    if (!ctx->initialized) return;
    
    if (ctx->entropy_kernel) clReleaseKernel(ctx->entropy_kernel);
    if (ctx->feature_extraction_kernel) clReleaseKernel(ctx->feature_extraction_kernel);
    if (ctx->svm_inference_kernel) clReleaseKernel(ctx->svm_inference_kernel);
    if (ctx->program) clReleaseProgram(ctx->program);
    if (ctx->command_queue) clReleaseCommandQueue(ctx->command_queue);
    if (ctx->context) clReleaseContext(ctx->context);
    
    memset(ctx, 0, sizeof(opencl_context_t));
    printf("OpenCL cleaned up\n");
}

int opencl_load_kernels(opencl_context_t *ctx, const char *kernel_path) {
    FILE *file;
    char *source_str;
    size_t source_size;
    cl_int err;
    
    // Read kernel source
    file = fopen(kernel_path, "r");
    if (!file) {
        fprintf(stderr, "Failed to open kernel file: %s\n", kernel_path);
        return -1;
    }
    
    fseek(file, 0, SEEK_END);
    source_size = ftell(file);
    rewind(file);
    
    source_str = (char*)malloc(source_size + 1);
    fread(source_str, 1, source_size, file);
    source_str[source_size] = '\0';
    fclose(file);
    
    // Create program
    ctx->program = clCreateProgramWithSource(ctx->context, 1, (const char**)&source_str,
                                            &source_size, &err);
    CHECK_OPENCL_ERROR(err, "Failed to create program");
    
    // Build program
    err = clBuildProgram(ctx->program, 1, &ctx->device, NULL, NULL, NULL);
    if (err != CL_SUCCESS) {
        size_t log_size;
        clGetProgramBuildInfo(ctx->program, ctx->device, CL_PROGRAM_BUILD_LOG, 
                             0, NULL, &log_size);
        char *log = (char*)malloc(log_size);
        clGetProgramBuildInfo(ctx->program, ctx->device, CL_PROGRAM_BUILD_LOG, 
                             log_size, log, NULL);
        fprintf(stderr, "Build log:\n%s\n", log);
        free(log);
        return -1;
    }
    
    // Create kernels
    ctx->entropy_kernel = clCreateKernel(ctx->program, "calculate_entropy", &err);
    CHECK_OPENCL_ERROR(err, "Failed to create entropy kernel");
    
    ctx->feature_extraction_kernel = clCreateKernel(ctx->program, "extract_features", &err);
    CHECK_OPENCL_ERROR(err, "Failed to create feature extraction kernel");
    
    ctx->svm_inference_kernel = clCreateKernel(ctx->program, "svm_inference", &err);
    CHECK_OPENCL_ERROR(err, "Failed to create SVM inference kernel");
    
    free(source_str);
    printf("Kernels loaded successfully\n");
    return 0;
}

int opencl_create_buffer(opencl_context_t *ctx, opencl_buffer_t *buf, 
                         size_t size, cl_mem_flags flags) {
    cl_int err;
    
    buf->buffer = clCreateBuffer(ctx->context, flags, size, NULL, &err);
    CHECK_OPENCL_ERROR(err, "Failed to create buffer");
    
    buf->size = size;
    buf->flags = flags;
    return 0;
}

int opencl_write_buffer(opencl_context_t *ctx, opencl_buffer_t *buf, 
                        const void *data, size_t size) {
    cl_int err;
    
    err = clEnqueueWriteBuffer(ctx->command_queue, buf->buffer, CL_TRUE, 0, 
                              size, data, 0, NULL, NULL);
    CHECK_OPENCL_ERROR(err, "Failed to write buffer");
    return 0;
}

int opencl_read_buffer(opencl_context_t *ctx, opencl_buffer_t *buf, 
                       void *data, size_t size) {
    cl_int err;
    
    err = clEnqueueReadBuffer(ctx->command_queue, buf->buffer, CL_TRUE, 0, 
                             size, data, 0, NULL, NULL);
    CHECK_OPENCL_ERROR(err, "Failed to read buffer");
    return 0;
}

void opencl_release_buffer(opencl_buffer_t *buf) {
    if (buf->buffer) {
        clReleaseMemObject(buf->buffer);
        buf->buffer = NULL;
    }
}

int opencl_execute_entropy_kernel(opencl_context_t *ctx, 
                                  opencl_buffer_t *ip_data,
                                  opencl_buffer_t *packet_counts,
                                  opencl_buffer_t *entropy_results,
                                  size_t num_ips, size_t window_size) {
    cl_int err;
    size_t global_work_size = num_ips;
    size_t local_work_size = (num_ips < 256) ? num_ips : 256; // Ensure local size doesn't exceed global
    
    // Set kernel arguments
    err = clSetKernelArg(ctx->entropy_kernel, 0, sizeof(cl_mem), &ip_data->buffer);
    CHECK_OPENCL_ERROR(err, "Failed to set kernel arg 0");
    
    err = clSetKernelArg(ctx->entropy_kernel, 1, sizeof(cl_mem), &packet_counts->buffer);
    CHECK_OPENCL_ERROR(err, "Failed to set kernel arg 1");
    
    err = clSetKernelArg(ctx->entropy_kernel, 2, sizeof(cl_mem), &entropy_results->buffer);
    CHECK_OPENCL_ERROR(err, "Failed to set kernel arg 2");
    
    err = clSetKernelArg(ctx->entropy_kernel, 3, sizeof(unsigned int), &window_size);
    CHECK_OPENCL_ERROR(err, "Failed to set kernel arg 3");
    
    // Execute kernel
    err = clEnqueueNDRangeKernel(ctx->command_queue, ctx->entropy_kernel, 1, NULL,
                                &global_work_size, &local_work_size, 0, NULL, NULL);
    CHECK_OPENCL_ERROR(err, "Failed to execute entropy kernel");
    
    return 0;
}

int opencl_execute_feature_extraction_kernel(opencl_context_t *ctx,
                                            opencl_buffer_t *flow_data,
                                            opencl_buffer_t *features,
                                            size_t num_flows) {
    cl_int err;
    size_t global_work_size = num_flows;
    // Let OpenCL runtime choose the local work size to avoid CL_INVALID_WORK_GROUP_SIZE
    const size_t *local_work_size_ptr = NULL;
    
    err = clSetKernelArg(ctx->feature_extraction_kernel, 0, sizeof(cl_mem), &flow_data->buffer);
    CHECK_OPENCL_ERROR(err, "Failed to set kernel arg 0");
    
    err = clSetKernelArg(ctx->feature_extraction_kernel, 1, sizeof(cl_mem), &features->buffer);
    CHECK_OPENCL_ERROR(err, "Failed to set kernel arg 1");
    
    err = clEnqueueNDRangeKernel(ctx->command_queue, ctx->feature_extraction_kernel, 1, NULL,
                                &global_work_size, local_work_size_ptr, 0, NULL, NULL);
    CHECK_OPENCL_ERROR(err, "Failed to execute feature extraction kernel");
    
    // Ensure kernel completion so wall-clock timing includes GPU execution
    err = clFinish(ctx->command_queue);
    CHECK_OPENCL_ERROR(err, "Failed to finish command queue after feature extraction kernel");
    
    return 0;
}

int opencl_execute_svm_kernel(opencl_context_t *ctx,
                             opencl_buffer_t *features,
                             opencl_buffer_t *svm_weights,
                             opencl_buffer_t *svm_support_vectors,
                             opencl_buffer_t *svm_bias,
                             opencl_buffer_t *predictions,
                             unsigned int num_samples,
                             unsigned int num_features,
                             unsigned int num_support_vectors,
                             float gamma) {
    cl_int err;
    size_t global_work_size = num_samples;
    // Let OpenCL runtime choose the local work size to avoid CL_INVALID_WORK_GROUP_SIZE
    const size_t *local_work_size_ptr = NULL;
    
    err = clSetKernelArg(ctx->svm_inference_kernel, 0, sizeof(cl_mem), &features->buffer);
    CHECK_OPENCL_ERROR(err, "Failed to set kernel arg 0");
    
    err = clSetKernelArg(ctx->svm_inference_kernel, 1, sizeof(cl_mem), &svm_weights->buffer);
    CHECK_OPENCL_ERROR(err, "Failed to set kernel arg 1");
    
    err = clSetKernelArg(ctx->svm_inference_kernel, 2, sizeof(cl_mem), &svm_support_vectors->buffer);
    CHECK_OPENCL_ERROR(err, "Failed to set kernel arg 2");
    
    err = clSetKernelArg(ctx->svm_inference_kernel, 3, sizeof(cl_mem), &svm_bias->buffer);
    CHECK_OPENCL_ERROR(err, "Failed to set kernel arg 3");
    
    err = clSetKernelArg(ctx->svm_inference_kernel, 4, sizeof(cl_mem), &predictions->buffer);
    CHECK_OPENCL_ERROR(err, "Failed to set kernel arg 4");
    
    err = clSetKernelArg(ctx->svm_inference_kernel, 5, sizeof(unsigned int), &num_samples);
    CHECK_OPENCL_ERROR(err, "Failed to set kernel arg 5");
    
    err = clSetKernelArg(ctx->svm_inference_kernel, 6, sizeof(unsigned int), &num_features);
    CHECK_OPENCL_ERROR(err, "Failed to set kernel arg 6");
    
    err = clSetKernelArg(ctx->svm_inference_kernel, 7, sizeof(unsigned int), &num_support_vectors);
    CHECK_OPENCL_ERROR(err, "Failed to set kernel arg 7");
    
    err = clSetKernelArg(ctx->svm_inference_kernel, 8, sizeof(float), &gamma);
    CHECK_OPENCL_ERROR(err, "Failed to set kernel arg 8");
    
    err = clEnqueueNDRangeKernel(ctx->command_queue, ctx->svm_inference_kernel, 1, NULL,
                                &global_work_size, local_work_size_ptr, 0, NULL, NULL);
    CHECK_OPENCL_ERROR(err, "Failed to execute SVM kernel");
    
    // Ensure kernel completion so wall-clock timing includes GPU execution
    err = clFinish(ctx->command_queue);
    CHECK_OPENCL_ERROR(err, "Failed to finish command queue after SVM kernel");
    
    return 0;
}

const char* opencl_get_error_string(cl_int error) {
    switch(error) {
        case CL_SUCCESS: return "CL_SUCCESS";
        case CL_DEVICE_NOT_FOUND: return "CL_DEVICE_NOT_FOUND";
        case CL_DEVICE_NOT_AVAILABLE: return "CL_DEVICE_NOT_AVAILABLE";
        case CL_COMPILER_NOT_AVAILABLE: return "CL_COMPILER_NOT_AVAILABLE";
        case CL_MEM_OBJECT_ALLOCATION_FAILURE: return "CL_MEM_OBJECT_ALLOCATION_FAILURE";
        case CL_OUT_OF_RESOURCES: return "CL_OUT_OF_RESOURCES";
        case CL_OUT_OF_HOST_MEMORY: return "CL_OUT_OF_HOST_MEMORY";
        case CL_PROFILING_INFO_NOT_AVAILABLE: return "CL_PROFILING_INFO_NOT_AVAILABLE";
        case CL_MEM_COPY_OVERLAP: return "CL_MEM_COPY_OVERLAP";
        case CL_IMAGE_FORMAT_MISMATCH: return "CL_IMAGE_FORMAT_MISMATCH";
        case CL_IMAGE_FORMAT_NOT_SUPPORTED: return "CL_IMAGE_FORMAT_NOT_SUPPORTED";
        case CL_BUILD_PROGRAM_FAILURE: return "CL_BUILD_PROGRAM_FAILURE";
        case CL_MAP_FAILURE: return "CL_MAP_FAILURE";
        case CL_MISALIGNED_SUB_BUFFER_OFFSET: return "CL_MISALIGNED_SUB_BUFFER_OFFSET";
        case CL_EXEC_STATUS_ERROR_FOR_EVENTS_IN_WAIT_LIST: return "CL_EXEC_STATUS_ERROR_FOR_EVENTS_IN_WAIT_LIST";
        case CL_COMPILE_PROGRAM_FAILURE: return "CL_COMPILE_PROGRAM_FAILURE";
        case CL_LINKER_NOT_AVAILABLE: return "CL_LINKER_NOT_AVAILABLE";
        case CL_LINK_PROGRAM_FAILURE: return "CL_LINK_PROGRAM_FAILURE";
        case CL_DEVICE_PARTITION_FAILED: return "CL_DEVICE_PARTITION_FAILED";
        case CL_KERNEL_ARG_INFO_NOT_AVAILABLE: return "CL_KERNEL_ARG_INFO_NOT_AVAILABLE";
        case CL_INVALID_VALUE: return "CL_INVALID_VALUE";
        case CL_INVALID_DEVICE_TYPE: return "CL_INVALID_DEVICE_TYPE";
        case CL_INVALID_PLATFORM: return "CL_INVALID_PLATFORM";
        case CL_INVALID_DEVICE: return "CL_INVALID_DEVICE";
        case CL_INVALID_CONTEXT: return "CL_INVALID_CONTEXT";
        case CL_INVALID_QUEUE_PROPERTIES: return "CL_INVALID_QUEUE_PROPERTIES";
        case CL_INVALID_COMMAND_QUEUE: return "CL_INVALID_COMMAND_QUEUE";
        case CL_INVALID_HOST_PTR: return "CL_INVALID_HOST_PTR";
        case CL_INVALID_MEM_OBJECT: return "CL_INVALID_MEM_OBJECT";
        case CL_INVALID_IMAGE_FORMAT_DESCRIPTOR: return "CL_INVALID_IMAGE_FORMAT_DESCRIPTOR";
        case CL_INVALID_IMAGE_SIZE: return "CL_INVALID_IMAGE_SIZE";
        case CL_INVALID_SAMPLER: return "CL_INVALID_SAMPLER";
        case CL_INVALID_BINARY: return "CL_INVALID_BINARY";
        case CL_INVALID_BUILD_OPTIONS: return "CL_INVALID_BUILD_OPTIONS";
        case CL_INVALID_PROGRAM: return "CL_INVALID_PROGRAM";
        case CL_INVALID_PROGRAM_EXECUTABLE: return "CL_INVALID_PROGRAM_EXECUTABLE";
        case CL_INVALID_KERNEL_NAME: return "CL_INVALID_KERNEL_NAME";
        case CL_INVALID_KERNEL_DEFINITION: return "CL_INVALID_KERNEL_DEFINITION";
        case CL_INVALID_KERNEL: return "CL_INVALID_KERNEL";
        case CL_INVALID_ARG_INDEX: return "CL_INVALID_ARG_INDEX";
        case CL_INVALID_ARG_VALUE: return "CL_INVALID_ARG_VALUE";
        case CL_INVALID_ARG_SIZE: return "CL_INVALID_ARG_SIZE";
        case CL_INVALID_KERNEL_ARGS: return "CL_INVALID_KERNEL_ARGS";
        case CL_INVALID_WORK_DIMENSION: return "CL_INVALID_WORK_DIMENSION";
        case CL_INVALID_WORK_GROUP_SIZE: return "CL_INVALID_WORK_GROUP_SIZE";
        case CL_INVALID_WORK_ITEM_SIZE: return "CL_INVALID_WORK_ITEM_SIZE";
        case CL_INVALID_GLOBAL_OFFSET: return "CL_INVALID_GLOBAL_OFFSET";
        case CL_INVALID_EVENT_WAIT_LIST: return "CL_INVALID_EVENT_WAIT_LIST";
        case CL_INVALID_EVENT: return "CL_INVALID_EVENT";
        case CL_INVALID_OPERATION: return "CL_INVALID_OPERATION";
        case CL_INVALID_GL_OBJECT: return "CL_INVALID_GL_OBJECT";
        case CL_INVALID_BUFFER_SIZE: return "CL_INVALID_BUFFER_SIZE";
        case CL_INVALID_MIP_LEVEL: return "CL_INVALID_MIP_LEVEL";
        case CL_INVALID_GLOBAL_WORK_SIZE: return "CL_INVALID_GLOBAL_WORK_SIZE";
        case CL_INVALID_PROPERTY: return "CL_INVALID_PROPERTY";
        case CL_INVALID_IMAGE_DESCRIPTOR: return "CL_INVALID_IMAGE_DESCRIPTOR";
        case CL_INVALID_COMPILER_OPTIONS: return "CL_INVALID_COMPILER_OPTIONS";
        case CL_INVALID_LINKER_OPTIONS: return "CL_INVALID_LINKER_OPTIONS";
        case CL_INVALID_DEVICE_PARTITION_COUNT: return "CL_INVALID_DEVICE_PARTITION_COUNT";
        default: return "Unknown error";
    }
}

void opencl_print_device_info(cl_device_id device) {
    char device_name[256];
    char device_vendor[256];
    char device_version[256];
    cl_uint compute_units;
    cl_ulong global_mem_size;
    size_t max_work_group_size;
    
    clGetDeviceInfo(device, CL_DEVICE_NAME, sizeof(device_name), device_name, NULL);
    clGetDeviceInfo(device, CL_DEVICE_VENDOR, sizeof(device_vendor), device_vendor, NULL);
    clGetDeviceInfo(device, CL_DEVICE_VERSION, sizeof(device_version), device_version, NULL);
    clGetDeviceInfo(device, CL_DEVICE_MAX_COMPUTE_UNITS, sizeof(compute_units), &compute_units, NULL);
    clGetDeviceInfo(device, CL_DEVICE_GLOBAL_MEM_SIZE, sizeof(global_mem_size), &global_mem_size, NULL);
    clGetDeviceInfo(device, CL_DEVICE_MAX_WORK_GROUP_SIZE, sizeof(max_work_group_size), &max_work_group_size, NULL);
    
    printf("OpenCL Device Info:\n");
    printf("  Name: %s\n", device_name);
    printf("  Vendor: %s\n", device_vendor);
    printf("  Version: %s\n", device_version);
    printf("  Compute Units: %u\n", compute_units);
    printf("  Global Memory: %llu MB\n", global_mem_size / (1024 * 1024));
    printf("  Max Work Group Size: %zu\n", max_work_group_size);
}

// Optional: NVML-based hardware GPU utilization (disabled unless USE_NVML is defined)
int opencl_query_gpu_utilization(opencl_context_t *ctx, float *utilization_percent) {
#ifdef USE_NVML
    // Placeholder for NVML integration. Requires linking against NVML and including nvml.h.
    // Return -1 to indicate not implemented in this build.
    (void)ctx;
    (void)utilization_percent;
    return -1;
#else
    (void)ctx;
    (void)utilization_percent;
    return -1;
#endif
}
