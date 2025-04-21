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

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for our operations
    if (size < 32) {
        return 0;
    }

    // Allocate memory for the arrays
    uint64_t* long8_array = (uint64_t*)safe_malloc(sizeof(uint64_t) * 4);
    uint32_t* long_array = (uint32_t*)safe_malloc(sizeof(uint32_t) * 4);
    float* float_array = (float*)safe_malloc(sizeof(float) * 4);
    uint8_t* bit_array = (uint8_t*)safe_malloc(sizeof(uint8_t) * 8);
    double* double_array = (double*)safe_malloc(sizeof(double) * 4);
    uint16_t* short_array = (uint16_t*)safe_malloc(sizeof(uint16_t) * 4);

    // Copy data into the arrays
    safe_memcpy(long8_array, data, sizeof(uint64_t) * 4);
    safe_memcpy(long_array, data + 32, sizeof(uint32_t) * 4);
    safe_memcpy(float_array, data + 48, sizeof(float) * 4);
    safe_memcpy(bit_array, data + 64, sizeof(uint8_t) * 8);
    safe_memcpy(double_array, data + 80, sizeof(double) * 4);
    safe_memcpy(short_array, data + 112, sizeof(uint16_t) * 4);

    // Perform the operations
    TIFFSwabArrayOfLong8(long8_array, 4);
    TIFFSwabArrayOfLong(long_array, 4);
    TIFFSwabArrayOfFloat(float_array, 4);
    TIFFReverseBits(bit_array, 8);
    TIFFSwabArrayOfDouble(double_array, 4);
    TIFFSwabArrayOfShort(short_array, 4);

    // Free allocated memory
    safe_free(long8_array);
    safe_free(long_array);
    safe_free(float_array);
    safe_free(bit_array);
    safe_free(double_array);
    safe_free(short_array);

    return 0;
}
