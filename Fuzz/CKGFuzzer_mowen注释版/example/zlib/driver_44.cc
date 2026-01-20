#include "zlib.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely extract an integer from the fuzz input
int safe_extract_int(const uint8_t* data, size_t size, size_t& offset, int min, int max) {
    if (offset + sizeof(int) > size) {
        return min; // Return the minimum value if not enough data
    }
    int value = *reinterpret_cast<const int*>(data + offset);
    offset += sizeof(int);
    return (value < min || value > max) ? min : value;
}

// Function to safely extract a size_t from the fuzz input
size_t safe_extract_size_t(const uint8_t* data, size_t size, size_t& offset) {
    if (offset + sizeof(size_t) > size) {
        return 0; // Return 0 if not enough data
    }
    size_t value = *reinterpret_cast<const size_t*>(data + offset);
    offset += sizeof(size_t);
    return value;
}

// Function to safely extract a pointer to a buffer from the fuzz input
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
    z_stream strm;
    memset(&strm, 0, sizeof(strm));

    // Extract parameters from fuzz input
    int bits = safe_extract_int(data, size, offset, 0, 16);
    int value = safe_extract_int(data, size, offset, 0, (1 << bits) - 1);
    int level = safe_extract_int(data, size, offset, 0, 9);
    int strategy = safe_extract_int(data, size, offset, 0, 2);
    size_t len2 = safe_extract_size_t(data, size, offset);
    size_t buffer_size;
    const uint8_t* buf = safe_extract_buffer(data, size, offset, buffer_size);
    size_t sourceLen = safe_extract_size_t(data, size, offset);

    // Initialize CRC
    unsigned long crc = 0;

    // Call inflatePrime
    int ret = inflatePrime(&strm, bits, value);
    if (ret != Z_OK) {
        return 0; // Handle error
    }

    // Call gzsetparams
    gzFile file = gzdopen(1, "wb"); // Use a dummy file descriptor for fuzzing
    if (file == nullptr) {
        return 0; // Handle error
    }
    ret = gzsetparams(file, level, strategy);
    if (ret != Z_OK) {
        gzclose(file);
        return 0; // Handle error
    }
    gzclose(file);

    // Call crc32_combine_gen
    uLong crc_gen = crc32_combine_gen(len2);

    // Call crc32_z
    if (buf != nullptr) {
        crc = crc32_z(crc, buf, buffer_size);
    }

    // Call deflateBound
    uLong bound = deflateBound(&strm, sourceLen);

    // Clean up
    deflateEnd(&strm);

    return 0;
}
