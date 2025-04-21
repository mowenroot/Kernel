#include "zlib.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely convert fuzz input to an integer
int safe_int_from_data(const uint8_t *data, size_t size, size_t offset, int min, int max) {
    if (offset + sizeof(int) > size) return 0; // Out of bounds
    int value = *reinterpret_cast<const int*>(data + offset);
    return (value < min || value > max) ? 0 : value;
}

// Function to safely convert fuzz input to a string
const char* safe_string_from_data(const uint8_t *data, size_t size, size_t offset, size_t max_len) {
    if (offset + max_len > size) return nullptr; // Out of bounds
    return reinterpret_cast<const char*>(data + offset);
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for basic operations
    if (size < 16) return 0;

    // Initialize variables
    z_stream strm;
    memset(&strm, 0, sizeof(strm));

    // Extract parameters from fuzz input
    int bits = safe_int_from_data(data, size, 0, 0, 16);
    int value = safe_int_from_data(data, size, sizeof(int), 0, (1 << bits) - 1);
    int level = safe_int_from_data(data, size, 2 * sizeof(int), 0, 9);
    int strategy = safe_int_from_data(data, size, 3 * sizeof(int), 0, 2);
    const char* mode = safe_string_from_data(data, size, 4 * sizeof(int), 4);

    // Ensure mode is valid
    if (!mode || (strcmp(mode, "rb") != 0 && strcmp(mode, "wb") != 0)) return 0;

    // Open a gzFile
    gzFile file = gzopen("input_file", mode);
    if (!file) return 0; // Failed to open file

    // Call inflatePrime
    int ret = inflatePrime(&strm, bits, value);
    if (ret != Z_OK) {
        gzclose(file);
        return 0;
    }

    // Call gzsetparams
    ret = gzsetparams(file, level, strategy);
    if (ret != Z_OK) {
        gzclose(file);
        return 0;
    }

    // Compute CRC32
    unsigned long crc = crc32_z(0L, data, size);

    // Close the gzFile
    ret = gzclose(file);
    if (ret != Z_OK) return 0;

    return 0;
}
