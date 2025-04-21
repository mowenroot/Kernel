#include "zlib.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely extract an integer from the fuzz input
int safe_extract_int(const uint8_t* data, size_t size, size_t& offset, int min, int max) {
    if (offset + sizeof(int) > size) {
        return min; // Default to minimum value if not enough data
    }
    int value = *reinterpret_cast<const int*>(data + offset);
    offset += sizeof(int);
    return (value < min) ? min : ((value > max) ? max : value);
}

// Function to safely extract a string from the fuzz input
const char* safe_extract_string(const uint8_t* data, size_t size, size_t& offset, size_t max_len) {
    if (offset + max_len > size) {
        return nullptr; // Not enough data for the string
    }
    const char* str = reinterpret_cast<const char*>(data + offset);
    offset += max_len;
    return str;
}

// Function to safely extract a buffer from the fuzz input
const uint8_t* safe_extract_buffer(const uint8_t* data, size_t size, size_t& offset, size_t& buf_size, size_t max_size) {
    if (offset + sizeof(size_t) > size) {
        return nullptr; // Not enough data for the buffer size
    }
    buf_size = *reinterpret_cast<const size_t*>(data + offset);
    offset += sizeof(size_t);
    if (buf_size > max_size || offset + buf_size > size) {
        return nullptr; // Buffer size exceeds limits or not enough data
    }
    const uint8_t* buf = data + offset;
    offset += buf_size;
    return buf;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    size_t offset = 0;
    gzFile file = nullptr;
    z_streamp strm = nullptr;
    int level, strategy;
    const char* mode;
    const uint8_t* dictionary;
    size_t dict_size;
    unsigned long crc;

    // Extract and validate inputs
    mode = safe_extract_string(data, size, offset, 10); // Assume mode string is at most 10 characters
    if (!mode) return 0;

    file = gzopen("input_file", mode);
    if (!file) return 0;

    level = safe_extract_int(data, size, offset, 0, 9); // zlib compression levels are 0-9
    strategy = safe_extract_int(data, size, offset, 0, 2); // zlib strategies are 0-2

    // Call gzsetparams
    int result = gzsetparams(file, level, strategy);
    if (result != Z_OK) {
        gzclose(file);
        return 0;
    }

    // Call gzclearerr
    gzclearerr(file);

    // Extract dictionary for deflateSetDictionary
    dictionary = safe_extract_buffer(data, size, offset, dict_size, 32 * 1024); // Limit dictionary size to 32KB
    if (!dictionary) {
        gzclose(file);
        return 0;
    }

    // Allocate and initialize z_stream
    strm = static_cast<z_streamp>(malloc(sizeof(z_stream)));
    if (!strm) {
        gzclose(file);
        return 0;
    }
    memset(strm, 0, sizeof(z_stream));

    // Call deflateSetDictionary
    result = deflateSetDictionary(strm, dictionary, static_cast<uInt>(dict_size));
    if (result != Z_OK) {
        free(strm);
        gzclose(file);
        return 0;
    }

    // Call crc32_z
    crc = crc32_z(0L, data, size);

    // Clean up
    free(strm);
    gzclose(file);

    return 0;
}
