#include "zlib.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely convert a uint8_t array to a string
char* safe_convert_to_string(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    char* str = (char*)malloc(size + 1);
    if (str == nullptr) return nullptr;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely convert a uint8_t array to an int
int safe_convert_to_int(const uint8_t* data, size_t size) {
    if (size == 0) return 0;
    int value = 0;
    for (size_t i = 0; i < size; ++i) {
        value = (value << 8) | data[i];
    }
    return value;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for our operations
    if (size < 12) return 0;

    // Extract parameters from the fuzz input
    size_t mode_size = data[0];
    size_t level_size = data[1];
    size_t strategy_size = data[2];
    size_t char_size = data[3];
    size_t crc_size = data[4];

    // Ensure the input size is sufficient for the extracted parameters
    if (size < (5 + mode_size + level_size + strategy_size + char_size + crc_size)) return 0;

    // Convert fuzz input to strings and integers
    char* mode = safe_convert_to_string(data + 5, mode_size);
    int level = safe_convert_to_int(data + 5 + mode_size, level_size);
    int strategy = safe_convert_to_int(data + 5 + mode_size + level_size, strategy_size);
    int c = safe_convert_to_int(data + 5 + mode_size + level_size + strategy_size, char_size);
    uint32_t crc = crc32_z(0, data + 5 + mode_size + level_size + strategy_size + char_size, crc_size);

    // Open a gzFile using gzdopen
    int fd = 1; // Use a dummy file descriptor for fuzzing
    gzFile file = gzdopen(fd, mode);
    if (file == nullptr) {
        free(mode);
        return 0;
    }

    // Set compression parameters using gzsetparams
    int setparams_result = gzsetparams(file, level, strategy);
    if (setparams_result != Z_OK) {
        gzclose(file);
        free(mode);
        return 0;
    }

    // Push a character back onto the input stream using gzungetc
    int ungetc_result = gzungetc(c, file);
    if (ungetc_result == -1) {
        gzclose(file);
        free(mode);
        return 0;
    }

    // Clear any error flags using gzclearerr
    gzclearerr(file);

    // Close the gzFile
    gzclose(file);

    // Free allocated memory
    free(mode);

    return 0;
}
