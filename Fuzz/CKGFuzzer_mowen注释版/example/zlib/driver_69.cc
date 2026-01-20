#include "zlib.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely extract an integer from the fuzz input
int safe_extract_int(const uint8_t *data, size_t size, size_t &offset, int max_value) {
    if (offset + sizeof(int) > size) {
        return 0; // Return a default value if not enough data
    }
    int value = *reinterpret_cast<const int*>(data + offset);
    offset += sizeof(int);
    return value % (max_value + 1); // Ensure value is within bounds
}

// Function to safely extract a string from the fuzz input
const char* safe_extract_string(const uint8_t *data, size_t size, size_t &offset, size_t max_length) {
    if (offset + max_length > size) {
        return nullptr; // Return nullptr if not enough data
    }
    const char* str = reinterpret_cast<const char*>(data + offset);
    offset += max_length;
    return str;
}

// Function to safely extract a buffer from the fuzz input
const uint8_t* safe_extract_buffer(const uint8_t *data, size_t size, size_t &offset, size_t max_length) {
    if (offset + max_length > size) {
        return nullptr; // Return nullptr if not enough data
    }
    const uint8_t* buffer = data + offset;
    offset += max_length;
    return buffer;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    size_t offset = 0;
    int fd = safe_extract_int(data, size, offset, 1024); // Arbitrary max file descriptor value
    const char* mode = safe_extract_string(data, size, offset, 10); // Arbitrary max mode length
    const uint8_t* dictionary = safe_extract_buffer(data, size, offset, 1024); // Arbitrary max dictionary length
    uInt dictLength = safe_extract_int(data, size, offset, 1024); // Arbitrary max dictionary length
    int bits = safe_extract_int(data, size, offset, 16); // Arbitrary max bits value
    int value = safe_extract_int(data, size, offset, 65535); // Arbitrary max value

    // Initialize zlib stream
    z_stream strm;
    memset(&strm, 0, sizeof(strm));

    // Open a gzFile handle
    gzFile gz = gzdopen(fd, mode);
    if (gz == nullptr) {
        return 0; // Handle error
    }

    // Set dictionary for deflate
    int ret = deflateSetDictionary(&strm, dictionary, dictLength);
    if (ret != Z_OK) {
        gzclose(gz);
        return 0; // Handle error
    }

    // Prime the inflate state
    ret = inflatePrime(&strm, bits, value);
    if (ret != Z_OK) {
        gzclose(gz);
        return 0; // Handle error
    }

    // Compute CRC-32 checksum
    unsigned long crc = crc32_z(0L, nullptr, 0);
    crc = crc32_z(crc, data, size);

    // Close the gzFile handle
    gzclose(gz);

    return 0; // Return success
}
