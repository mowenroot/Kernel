#include <zlib.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy a string from fuzz input
char* safe_strndup(const uint8_t* data, size_t size) {
    size_t len = strnlen((const char*)data, size);
    char* str = (char*)malloc(len + 1);
    if (str) {
        memcpy(str, data, len);
        str[len] = '\0';
    }
    return str;
}

// Function to safely convert fuzz input to an integer
int safe_atoi(const uint8_t* data, size_t size) {
    char* str = safe_strndup(data, size);
    if (!str) return 0;
    int value = atoi(str);
    free(str);
    return value;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for the operations
    if (size < 10) return 0;

    // Extract parameters from fuzz input
    const char* mode = (const char*)data;
    int level = safe_atoi(data + 1, 4);
    int strategy = safe_atoi(data + 5, 4);
    int flush = safe_atoi(data + 9, 1);

    // Open the gzip file
    gzFile file = gzopen("input_file", mode);
    if (!file) return 0;

    // Set compression parameters
    int setparams_result = gzsetparams(file, level, strategy);
    if (setparams_result != Z_OK) {
        gzclose_r(file);
        return 0;
    }

    // Flush the file
    int flush_result = gzflush(file, flush);
    if (flush_result != Z_OK) {
        gzclose_r(file);
        return 0;
    }

    // Check for errors
    int errnum;
    const char* error_msg = gzerror(file, &errnum);
    if (errnum != Z_OK) {
        // Handle error (log or ignore)
    }

    // Close the file
    int close_result = gzclose_r(file);
    if (close_result != Z_OK) {
        // Handle error (log or ignore)
    }

    return 0;
}
