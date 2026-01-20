#include <zlib.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy a string from fuzz input
char* safe_strndup(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    char* str = (char*)malloc(size + 1);
    if (!str) return nullptr;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely allocate memory for a buffer
void* safe_malloc(size_t size) {
    if (size == 0) return nullptr;
    void* ptr = malloc(size);
    if (!ptr) abort(); // Handle allocation failure
    return ptr;
}

// Function to safely free memory
void safe_free(void* ptr) {
    if (ptr) free(ptr);
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for file mode and content
    if (size < 2) return 0;

    // Extract file mode from fuzz input
    const char* mode = (data[0] % 2 == 0) ? "wb" : "rb";
    data++; size--; // Move past mode byte

    // Open the file using gzopen
    gzFile file = gzopen("input_file", mode);
    if (!file) return 0; // Failed to open file

    // Handle read and write operations based on mode
    if (strcmp(mode, "wb") == 0) {
        // Write mode
        size_t write_size = (size > 1024) ? 1024 : size; // Limit write size to 1024 bytes
        int written = gzwrite(file, data, write_size);
        if (written < 0) {
            gzclose_w(file);
            return 0; // Write failed
        }
    } else if (strcmp(mode, "rb") == 0) {
        // Read mode
        uint8_t* read_buffer = (uint8_t*)safe_malloc(1024); // Allocate buffer for reading
        if (!read_buffer) {
            gzclose_r(file);
            return 0; // Allocation failed
        }
        int read = gzread(file, read_buffer, 1024);
        if (read < 0) {
            safe_free(read_buffer);
            gzclose_r(file);
            return 0; // Read failed
        }
        safe_free(read_buffer);
    }

    // Close the file based on mode
    if (strcmp(mode, "wb") == 0) {
        gzclose_w(file);
    } else if (strcmp(mode, "rb") == 0) {
        gzclose_r(file);
    }

    return 0;
}
