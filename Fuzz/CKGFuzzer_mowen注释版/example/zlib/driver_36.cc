#include "zlib.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely extract an integer from the fuzz input
int safe_extract_int(const uint8_t* data, size_t size, size_t& offset, int max_bits) {
    if (offset + sizeof(int) > size) {
        return 0; // Return a default value if not enough data
    }
    int value = *reinterpret_cast<const int*>(data + offset);
    offset += sizeof(int);
    return value & ((1 << max_bits) - 1); // Limit the value to max_bits
}

// Function to safely extract a size_t from the fuzz input
size_t safe_extract_size_t(const uint8_t* data, size_t size, size_t& offset) {
    if (offset + sizeof(size_t) > size) {
        return 0; // Return a default value if not enough data
    }
    size_t value = *reinterpret_cast<const size_t*>(data + offset);
    offset += sizeof(size_t);
    return value;
}

// Function to safely extract a buffer from the fuzz input
const uint8_t* safe_extract_buffer(const uint8_t* data, size_t size, size_t& offset, size_t& buffer_size) {
    buffer_size = safe_extract_size_t(data, size, offset);
    if (offset + buffer_size > size) {
        buffer_size = 0; // Reset buffer size if not enough data
        return nullptr;
    }
    const uint8_t* buffer = data + offset;
    offset += buffer_size;
    return buffer;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    size_t offset = 0;
    int ret;

    // Create a z_stream for inflate operations
    z_stream strm;
    memset(&strm, 0, sizeof(strm));

    // Initialize inflate state
    ret = inflateInit2(&strm, -MAX_WBITS);
    if (ret != Z_OK) {
        return 0; // Early exit on error
    }

    // Extract parameters from fuzz input
    int bits = safe_extract_int(data, size, offset, 16);
    int value = safe_extract_int(data, size, offset, 16);
    int windowBits = safe_extract_int(data, size, offset, 15);
    size_t buffer_size;
    const uint8_t* buffer = safe_extract_buffer(data, size, offset, buffer_size);

    // Call inflatePrime
    ret = inflatePrime(&strm, bits, value);
    if (ret != Z_OK) {
        inflateEnd(&strm);
        return 0; // Early exit on error
    }

    // Call inflateReset2
    ret = inflateReset2(&strm, windowBits);
    if (ret != Z_OK) {
        inflateEnd(&strm);
        return 0; // Early exit on error
    }

    // Compute CRC32
    unsigned long crc = crc32_z(0L, nullptr, 0);
    if (buffer) {
        crc = crc32_z(crc, buffer, buffer_size);
    }

    // Check deflatePending
    unsigned pending;
    int pending_bits;
    ret = deflatePending(&strm, &pending, &pending_bits);
    if (ret != Z_OK) {
        inflateEnd(&strm);
        return 0; // Early exit on error
    }

    // Clean up
    inflateEnd(&strm);

    // Simulate gzclose_r by freeing resources (no actual file operations in fuzzing)
    // This is a placeholder since gzclose_r is not directly usable in this context
    // but we ensure all resources are freed properly.

    return 0; // Return 0 to indicate success
}
