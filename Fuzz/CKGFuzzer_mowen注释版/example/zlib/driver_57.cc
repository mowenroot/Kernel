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

// Function to safely convert fuzz input to an integer
int safe_atoi(const uint8_t* data, size_t size) {
    if (size == 0) return 0;
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

    // Extract file mode from fuzz input
    const char* mode = (data[0] % 2 == 0) ? "wb" : "rb";

    // Open the gzip file
    gzFile file = gzopen("output_file", mode);
    if (!file) return 0;

    // Check for errors using gzerror
    int errnum = 0;
    const char* error_msg = gzerror(file, &errnum);
    if (errnum != Z_OK) {
        gzclose(file);
        return 0;
    }

    // If writing, perform gzflush with a flush mode derived from fuzz input
    if (mode[0] == 'w') {
        int flush_mode = data[1] % 5; // Z_NO_FLUSH to Z_FINISH
        int flush_result = gzflush(file, flush_mode);
        if (flush_result != Z_OK) {
            gzclose(file);
            return 0;
        }
    }

    // Check if end of file is reached using gzeof
    int eof_result = gzeof(file);

    // Close the file using gzclose_w if writing, otherwise gzclose
    int close_result = (mode[0] == 'w') ? gzclose_w(file) : gzclose(file);
    if (close_result != Z_OK) {
        return 0;
    }

    return 0;
}
