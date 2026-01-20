#include "zlib.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely extract an integer from the fuzz input
int extractInt(const uint8_t* data, size_t size, size_t& offset, int min, int max) {
    if (offset + sizeof(int) > size) {
        return min; // Default to min value if not enough data
    }
    int value = *reinterpret_cast<const int*>(data + offset);
    offset += sizeof(int);
    return (value < min) ? min : ((value > max) ? max : value);
}

// Function to safely extract a string from the fuzz input
const char* extractString(const uint8_t* data, size_t size, size_t& offset, size_t maxLen) {
    if (offset + maxLen > size) {
        return nullptr; // Not enough data
    }
    const char* str = reinterpret_cast<const char*>(data + offset);
    offset += maxLen;
    return str;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < sizeof(int) * 3 + 1) {
        return 0; // Not enough data to proceed
    }

    // Extract parameters from fuzz input
    size_t offset = 0;
    int level = extractInt(data, size, offset, 0, 9); // zlib compression levels are 0-9
    int strategy = extractInt(data, size, offset, 0, 2); // zlib strategies are 0-2
    size_t dataSize = extractInt(data, size, offset, 0, 1024); // Limit data size to 1024 bytes

    // Ensure we have enough data for the specified dataSize
    if (offset + dataSize > size) {
        return 0; // Not enough data to proceed
    }

    // Open a gzip file for writing
    gzFile file = gzopen("output_file", "wb");
    if (file == nullptr) {
        return 0; // Failed to open file
    }

    // Set compression parameters
    int setParamsResult = gzsetparams(file, level, strategy);
    if (setParamsResult != Z_OK) {
        gzclose(file);
        return 0; // Failed to set parameters
    }

    // Write data to the gzip file
    z_size_t bytesWritten = gzfwrite(data + offset, 1, dataSize, file);
    if (bytesWritten != dataSize) {
        gzclose(file);
        return 0; // Failed to write data
    }

    // Compute CRC32 of the written data
    unsigned long crc = crc32_z(0L, nullptr, 0);
    crc = crc32_z(crc, data + offset, dataSize);

    // Close the gzip file
    int closeResult = gzclose(file);
    if (closeResult != Z_OK) {
        return 0; // Failed to close file
    }

    return 0; // Success
}
