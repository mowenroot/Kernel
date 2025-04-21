#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

// Function to safely allocate memory and handle errors
void* safe_malloc(size_t size) {
    void* ptr = malloc(size);
    if (!ptr) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    return ptr;
}

// Function to safely reallocate memory and handle errors
void* safe_realloc(void* ptr, size_t size) {
    void* new_ptr = realloc(ptr, size);
    if (!new_ptr) {
        fprintf(stderr, "Memory reallocation failed\n");
        free(ptr);
        exit(1);
    }
    return new_ptr;
}

// Function to safely free allocated memory
void safe_free(void* ptr) {
    if (ptr) {
        free(ptr);
    }
}

// Function to safely copy data and handle errors
void safe_memcpy(void* dest, const void* src, size_t n) {
    if (n > 0) {
        memcpy(dest, src, n);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for at least one call
    if (size < sizeof(uint64_t) + sizeof(uint32_t) + sizeof(uint16_t) + sizeof(double) + sizeof(uint16_t) + sizeof(uint32_t)) {
        return 0;
    }

    // Allocate memory for the arrays
    uint64_t* long8_array = (uint64_t*)safe_malloc(sizeof(uint64_t) * 1);
    uint32_t* long_array = (uint32_t*)safe_malloc(sizeof(uint32_t) * 1);
    uint16_t* short_array = (uint16_t*)safe_malloc(sizeof(uint16_t) * 1);
    double* double_array = (double*)safe_malloc(sizeof(double) * 1);
    uint16_t* short_array2 = (uint16_t*)safe_malloc(sizeof(uint16_t) * 1);
    uint32_t* long_value = (uint32_t*)safe_malloc(sizeof(uint32_t) * 1);

    // Copy data from fuzz input to arrays
    safe_memcpy(long8_array, data, sizeof(uint64_t));
    safe_memcpy(long_array, data + sizeof(uint64_t), sizeof(uint32_t));
    safe_memcpy(short_array, data + sizeof(uint64_t) + sizeof(uint32_t), sizeof(uint16_t));
    safe_memcpy(double_array, data + sizeof(uint64_t) + sizeof(uint32_t) + sizeof(uint16_t), sizeof(double));
    safe_memcpy(short_array2, data + sizeof(uint64_t) + sizeof(uint32_t) + sizeof(uint16_t) + sizeof(double), sizeof(uint16_t));
    safe_memcpy(long_value, data + sizeof(uint64_t) + sizeof(uint32_t) + sizeof(uint16_t) + sizeof(double) + sizeof(uint16_t), sizeof(uint32_t));

    // Call the API functions
    TIFFSwabArrayOfLong8(long8_array, 1);
    TIFFSwabArrayOfLong(long_array, 1);
    TIFFSwabShort(short_array);
    TIFFSwabArrayOfDouble(double_array, 1);
    TIFFSwabArrayOfShort(short_array2, 1);
    TIFFSwabLong(long_value);

    // Free allocated memory
    safe_free(long8_array);
    safe_free(long_array);
    safe_free(short_array);
    safe_free(double_array);
    safe_free(short_array2);
    safe_free(long_value);

    return 0;
}
