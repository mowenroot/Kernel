#include "zlib.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely extract an integer from the fuzz input
int extractInt(const uint8_t*& data, size_t& size, size_t maxSize) {
    if (size < maxSize) return 0; // Default value if not enough data
    int value = 0;
    for (size_t i = 0; i < maxSize; ++i) {
        value |= (data[i] << (8 * i));
    }
    data += maxSize;
    size -= maxSize;
    return value;
}

// Function to safely extract a string from the fuzz input
const char* extractString(const uint8_t*& data, size_t& size, size_t maxSize) {
    if (size < maxSize) return nullptr; // Default value if not enough data
    const char* str = reinterpret_cast<const char*>(data);
    data += maxSize;
    size -= maxSize;
    return str;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize zlib stream
    z_stream strm;
    memset(&strm, 0, sizeof(strm));

    // Initialize gz_header
    gz_header header;
    memset(&header, 0, sizeof(header));

    // Extract parameters from fuzz input
    int windowBits = extractInt(data, size, sizeof(int));
    int level = extractInt(data, size, sizeof(int));
    int strategy = extractInt(data, size, sizeof(int));
    const char* fileName = extractString(data, size, 256); // Assuming max file name length of 256

    // Initialize zlib stream for deflate
    int ret = deflateInit2(&strm, level, Z_DEFLATED, windowBits, 8, strategy);
    if (ret != Z_OK) {
        deflateEnd(&strm);
        return 0;
    }

    // Set deflate parameters
    ret = deflateParams(&strm, level, strategy);
    if (ret != Z_OK) {
        deflateEnd(&strm);
        return 0;
    }

    // Set deflate header
    ret = deflateSetHeader(&strm, &header);
    if (ret != Z_OK) {
        deflateEnd(&strm);
        return 0;
    }

    // Initialize zlib stream for inflate
    ret = inflateInit2(&strm, windowBits);
    if (ret != Z_OK) {
        deflateEnd(&strm);
        inflateEnd(&strm);
        return 0;
    }

    // Reset inflate state
    ret = inflateReset2(&strm, windowBits);
    if (ret != Z_OK) {
        deflateEnd(&strm);
        inflateEnd(&strm);
        return 0;
    }

    // Compute CRC32
    unsigned long crc = crc32_z(0L, data, size);

    // Clean up
    deflateEnd(&strm);
    inflateEnd(&strm);

    return 0;
}
