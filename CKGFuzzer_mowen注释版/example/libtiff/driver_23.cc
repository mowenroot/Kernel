#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

// Function to safely allocate memory
void* safe_malloc(size_t size) {
    void* ptr = malloc(size);
    if (!ptr) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    return ptr;
}

// Function to safely reallocate memory
void* safe_realloc(void* ptr, size_t size) {
    void* new_ptr = realloc(ptr, size);
    if (!new_ptr) {
        fprintf(stderr, "Memory reallocation failed\n");
        free(ptr);
        exit(1);
    }
    return new_ptr;
}

// Function to safely free memory
void safe_free(void* ptr) {
    if (ptr) {
        free(ptr);
    }
}

// Function to safely copy data
void safe_memcpy(void* dest, const void* src, size_t n) {
    if (n > 0) {
        memcpy(dest, src, n);
    }
}

// Function to safely set memory
void safe_memset(void* s, int c, size_t n) {
    if (n > 0) {
        memset(s, c, n);
    }
}

// Function to safely cast data
template <typename T>
T* safe_cast(void* ptr) {
    if (!ptr) {
        fprintf(stderr, "Invalid pointer cast\n");
        exit(1);
    }
    return static_cast<T*>(ptr);
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input data size is sufficient for all operations
    if (size < sizeof(uint64_t) + sizeof(uint8_t) * 3 + sizeof(uint32_t) + sizeof(float) + sizeof(double) + sizeof(uint16_t)) {
        return 0;
    }

    // Allocate memory for the arrays
    uint64_t* long8_array = static_cast<uint64_t*>(safe_malloc(sizeof(uint64_t)));
    uint8_t* triple_array = static_cast<uint8_t*>(safe_malloc(sizeof(uint8_t) * 3));
    uint32_t* long_array = static_cast<uint32_t*>(safe_malloc(sizeof(uint32_t)));
    float* float_array = static_cast<float*>(safe_malloc(sizeof(float)));
    double* double_array = static_cast<double*>(safe_malloc(sizeof(double)));
    uint16_t* short_array = static_cast<uint16_t*>(safe_malloc(sizeof(uint16_t)));

    // Copy data into the arrays
    safe_memcpy(long8_array, data, sizeof(uint64_t));
    safe_memcpy(triple_array, data + sizeof(uint64_t), sizeof(uint8_t) * 3);
    safe_memcpy(long_array, data + sizeof(uint64_t) + sizeof(uint8_t) * 3, sizeof(uint32_t));
    safe_memcpy(float_array, data + sizeof(uint64_t) + sizeof(uint8_t) * 3 + sizeof(uint32_t), sizeof(float));
    safe_memcpy(double_array, data + sizeof(uint64_t) + sizeof(uint8_t) * 3 + sizeof(uint32_t) + sizeof(float), sizeof(double));
    safe_memcpy(short_array, data + sizeof(uint64_t) + sizeof(uint8_t) * 3 + sizeof(uint32_t) + sizeof(float) + sizeof(double), sizeof(uint16_t));

    // Call the API functions
    TIFFSwabArrayOfLong8(long8_array, 1);
    TIFFSwabArrayOfTriples(triple_array, 1);
    TIFFSwabArrayOfLong(long_array, 1);
    TIFFSwabArrayOfFloat(float_array, 1);
    TIFFSwabArrayOfDouble(double_array, 1);
    TIFFSwabArrayOfShort(short_array, 1);

    // Free allocated memory
    safe_free(long8_array);
    safe_free(triple_array);
    safe_free(long_array);
    safe_free(float_array);
    safe_free(double_array);
    safe_free(short_array);

    return 0;
}
