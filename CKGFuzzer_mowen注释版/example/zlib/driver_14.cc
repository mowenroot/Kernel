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
const uint8_t* safe_extract_buffer(const uint8_t* data, size_t size, size_t& offset, size_t& buf_size, size_t max_len) {
    if (offset + max_len > size) {
        return nullptr; // Not enough data for the buffer
    }
    const uint8_t* buf = data + offset;
    buf_size = max_len;
    offset += max_len;
    return buf;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    size_t offset = 0;
    gzFile file = nullptr;
    z_streamp strm = nullptr;
    const char* mode = "wb"; // Default mode for gzopen
    const char* filename = "output_file"; // Default filename for gzopen
    int level = 6; // Default compression level
    int strategy = Z_DEFAULT_STRATEGY; // Default compression strategy
    unsigned long crc = 0;
    const uint8_t* dictionary = nullptr;
    size_t dict_size = 0;

    // Extract parameters from fuzz input
    level = safe_extract_int(data, size, offset, 0, 9); // zlib compression levels are 0-9
    strategy = safe_extract_int(data, size, offset, 0, 2); // zlib strategies are 0-2
    mode = safe_extract_string(data, size, offset, 3); // Mode string is at most 3 characters
    filename = safe_extract_string(data, size, offset, 256); // Filename is at most 256 characters
    dictionary = safe_extract_buffer(data, size, offset, dict_size, 32768); // Dictionary size is at most 32KB

    // Open the gzip file
    file = gzopen(filename, mode);
    if (file == nullptr) {
        return 0; // Failed to open file
    }

    // Set compression parameters
    if (gzsetparams(file, level, strategy) != Z_OK) {
        gzclose(file);
        return 0; // Failed to set parameters
    }

    // Set dictionary for compression
    if (dictionary != nullptr && dict_size > 0) {
        strm = reinterpret_cast<z_streamp>(file); // Corrected the type cast
        if (strm != nullptr && deflateSetDictionary(strm, dictionary, dict_size) != Z_OK) {
            gzclose(file);
            return 0; // Failed to set dictionary
        }
    }

    // Compute CRC32 for the input data
    crc = crc32_z(crc, data, size);

    // Clear any errors
    gzclearerr(file);

    // Close the file
    gzclose(file);

    return 0; // Success
}
