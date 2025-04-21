#include "zlib.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely convert a uint8_t array to an integer
int safe_to_int(const uint8_t* data, size_t size, size_t offset, int max_bits) {
    int value = 0;
    for (size_t i = 0; i < max_bits && i + offset < size; ++i) {
        value |= (data[i + offset] & 0x01) << i;
    }
    return value;
}

// Function to safely convert a uint8_t array to a string
const char* safe_to_string(const uint8_t* data, size_t size, size_t offset, size_t max_length) {
    static char buffer[256];
    size_t length = size - offset < max_length ? size - offset : max_length;
    memcpy(buffer, data + offset, length);
    buffer[length] = '\0';
    return buffer;
}

// Function to safely convert a uint8_t array to a uLong
uLong safe_to_uLong(const uint8_t* data, size_t size, size_t offset, size_t max_bytes) {
    uLong value = 0;
    for (size_t i = 0; i < max_bytes && i + offset < size; ++i) {
        value |= (uLong)(data[i + offset]) << (i * 8);
    }
    return value;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    z_stream strm;
    memset(&strm, 0, sizeof(strm));

    // Ensure we have enough data for basic operations
    if (size < 16) return 0;

    // Extract parameters from fuzz input
    int bits = safe_to_int(data, size, 0, 8);
    int value = safe_to_int(data, size, 1, 16);
    uLong crc1 = safe_to_uLong(data, size, 3, 4);
    uLong crc2 = safe_to_uLong(data, size, 7, 4);
    uLong op = safe_to_uLong(data, size, 11, 4);
    const char* mode = safe_to_string(data, size, 15, 8);
    uInt dictLength = size > 23 ? size - 23 : 0;

    // Call inflatePrime
    int ret = inflatePrime(&strm, bits, value);
    if (ret != Z_OK) {
        return 0; // Handle error
    }

    // Call crc32_combine_op
    uLong combined_crc = crc32_combine_op(crc1, crc2, op);

    // Call gzdopen
    int fd = 1; // Dummy file descriptor
    gzFile gz = gzdopen(fd, mode);
    if (gz == NULL) {
        return 0; // Handle error
    }

    // Call deflateSetDictionary
    Bytef* dictionary = (Bytef*)(data + 23);
    ret = deflateSetDictionary(&strm, dictionary, dictLength);
    if (ret != Z_OK) {
        return 0; // Handle error
    }

    // Call crc32_z
    uLong crc = crc32_z(0L, data, size);

    // Clean up
    deflateEnd(&strm);
    gzclose(gz);

    return 0;
}
