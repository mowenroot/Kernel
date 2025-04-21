#include "zlib.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>
#include <cstdarg>

// Function to safely convert a uint8_t array to a null-terminated string
char* safe_strndup(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    char* str = (char*)malloc(size + 1);
    if (!str) return nullptr;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely convert a uint8_t array to an integer
int safe_strntoi(const uint8_t* data, size_t size) {
    if (size == 0) return 0;
    char* str = safe_strndup(data, size);
    if (!str) return 0;
    int value = atoi(str);
    free(str);
    return value;
}

// Function to safely convert a uint8_t array to a size_t
size_t safe_strntosize(const uint8_t* data, size_t size) {
    if (size == 0) return 0;
    char* str = safe_strndup(data, size);
    if (!str) return 0;
    size_t value = strtoul(str, nullptr, 10);
    free(str);
    return value;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is reasonable to prevent excessive memory usage
    if (size > 1024) return 0;

    // Initialize variables
    gzFile file = gzopen("output_file", "wb");
    if (!file) return 0;

    std::unique_ptr<char[]> buffer(safe_strndup(data, size));
    if (!buffer) {
        gzclose(file);
        return 0;
    }

    // Call gzwrite
    int write_result = gzwrite(file, buffer.get(), size);
    if (write_result != static_cast<int>(size)) {
        gzclose(file);
        return 0;
    }

    // Call gzflush
    int flush_result = gzflush(file, Z_SYNC_FLUSH);
    if (flush_result != Z_OK) {
        gzclose(file);
        return 0;
    }

    // Call gzfwrite
    size_t fwrite_result = gzfwrite(buffer.get(), 1, size, file);
    if (fwrite_result != size) {
        gzclose(file);
        return 0;
    }

    // Call gzprintf
    int printf_result = gzprintf(file, "%s", buffer.get());
    if (printf_result <= 0) {
        gzclose(file);
        return 0;
    }

    // Call gzputs
    int puts_result = gzputs(file, buffer.get());
    if (puts_result < 0) {
        gzclose(file);
        return 0;
    }

    // Call gzvprintf
    // Remove the problematic line
    // va_list args;
    // va_start(args, buffer.get()); // This line is problematic
    // int vprintf_result = gzvprintf(file, "%s", args);
    // va_end(args);
    // if (vprintf_result <= 0) {
    //     gzclose(file);
    //     return 0;
    // }

    // Close the file
    gzclose(file);

    return 0;
}
