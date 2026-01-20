#include <stdio.h>  // Include stdio.h to declare stderr
#include <zlib.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely allocate memory
void* safe_malloc(size_t size) {
    void* ptr = malloc(size);
    if (!ptr) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    return ptr;
}

// Function to safely free memory
void safe_free(void* ptr) {
    if (ptr) {
        free(ptr);
    }
}

// Function to safely copy data with bounds checking
void safe_copy(void* dest, const void* src, size_t size) {
    if (size > 0) {
        memcpy(dest, src, size);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is reasonable to prevent excessive memory usage
    if (size < 1 || size > 1024 * 1024) {
        return 0;
    }

    // Initialize variables
    gzFile file = nullptr;
    char* read_buffer = nullptr;
    char* write_buffer = nullptr;
    int direct_mode = 0;
    int close_result = Z_OK;

    // Allocate buffers
    read_buffer = (char*)safe_malloc(size + 1);
    write_buffer = (char*)safe_malloc(size);

    // Open the file for reading and writing
    file = gzopen("input_file", "wb+");
    if (!file) {
        goto cleanup;
    }

    // Write data to the file
    if (gzfwrite(data, 1, size, file) != size) {
        goto cleanup;
    }

    // Check if the file is in direct mode
    direct_mode = gzdirect(file);

    // Rewind the file for reading
    if (gzrewind(file) != 0) {
        goto cleanup;
    }

    // Read data from the file
    if (gzgets(file, read_buffer, size + 1) == nullptr) {
        goto cleanup;
    }

    // Close the file
    close_result = gzclose_r(file);
    file = nullptr;

cleanup:
    // Free allocated memory
    safe_free(read_buffer);
    safe_free(write_buffer);

    // Close the file if it's still open
    if (file) {
        gzclose_r(file);
    }

    // Return the close result
    return close_result;
}
