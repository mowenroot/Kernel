#include <stdio.h> // Add this include to declare stderr
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

// Function to safely copy a string
char* safe_strncpy(char* dest, const char* src, size_t n) {
    if (n == 0) return dest;
    char* d = dest;
    while (n-- > 1 && (*d++ = *src++));
    *d = '\0';
    return dest;
}

// Function to safely read a string from fuzz input
char* safe_read_string(const uint8_t* data, size_t size, size_t max_len) {
    size_t len = size < max_len ? size : max_len;
    char* str = (char*)safe_malloc(len + 1);
    memcpy(str, data, len);
    str[len] = '\0';
    return str;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for the file mode and some content
    if (size < 2) return 0;

    // Extract the file mode from the fuzz input
    const char* mode = (data[0] % 2 == 0) ? "rb" : "wb";

    // Open the gzip file
    gzFile file = gzopen("input_file", mode);
    if (!file) {
        return 0; // Failed to open file
    }

    // Read and write operations based on the mode
    if (strcmp(mode, "rb") == 0) {
        // Reading mode
        char* buf = (char*)safe_malloc(size);
        if (gzread(file, buf, size) != size) { // Use gzread instead of gzfread
            free(buf);
            gzclose(file); // Use gzclose instead of gzclose_r
            return 0; // Failed to read
        }
        free(buf);

        char* line_buf = (char*)safe_malloc(size + 1);
        if (gzgets(file, line_buf, size) == NULL) {
            free(line_buf);
            gzclose(file); // Use gzclose instead of gzclose_r
            return 0; // Failed to read line
        }
        free(line_buf);
    } else if (strcmp(mode, "wb") == 0) {
        // Writing mode
        if (gzflush(file, Z_SYNC_FLUSH) != Z_OK) {
            gzclose(file); // Use gzclose instead of gzclose_r
            return 0; // Failed to flush
        }
    }

    // Close the file
    if (gzclose(file) != Z_OK) { // Use gzclose instead of gzclose_r
        return 0; // Failed to close file
    }

    return 0;
}
