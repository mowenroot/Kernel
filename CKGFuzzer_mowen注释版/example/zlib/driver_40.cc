#include "zlib.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely extract an integer from the fuzz input
int safe_extract_int(const uint8_t* data, size_t size, size_t& offset, int min_val, int max_val) {
    if (offset + sizeof(int) > size) {
        return min_val; // Default to minimum value if not enough data
    }
    int value = *reinterpret_cast<const int*>(data + offset);
    offset += sizeof(int);
    return (value < min_val || value > max_val) ? min_val : value;
}

// Function to safely extract a size_t from the fuzz input
size_t safe_extract_size_t(const uint8_t* data, size_t size, size_t& offset) {
    if (offset + sizeof(size_t) > size) {
        return 0; // Default to 0 if not enough data
    }
    size_t value = *reinterpret_cast<const size_t*>(data + offset);
    offset += sizeof(size_t);
    return value;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    size_t offset = 0;
    int level = safe_extract_int(data, size, offset, 0, 9); // Zlib compression levels are 0-9
    int strategy = safe_extract_int(data, size, offset, 0, 2); // Zlib strategies are 0-2
    int flush = safe_extract_int(data, size, offset, 0, Z_FINISH); // Flush modes are 0-Z_FINISH
    size_t len2 = safe_extract_size_t(data, size, offset);

    // Create a temporary file for writing
    gzFile file = gzopen("output_file", "wb");
    if (file == nullptr) {
        return 0; // Failed to open file
    }

    // Set compression parameters
    int setparams_result = gzsetparams(file, level, strategy);
    if (setparams_result != Z_OK) {
        gzclose_w(file);
        return 0; // Failed to set parameters
    }

    // Write some data to the file (dummy data for fuzzing purposes)
    const char* dummy_data = "dummy data";
    gzwrite(file, dummy_data, strlen(dummy_data));

    // Flush the file
    int flush_result = gzflush(file, flush);
    if (flush_result != Z_OK) {
        gzclose_w(file);
        return 0; // Failed to flush
    }

    // Close the file
    int close_result = gzclose_w(file);
    if (close_result != Z_OK) {
        return 0; // Failed to close file
    }

    // Calculate CRC32 combine generation
    uLong crc32_result = crc32_combine_gen(len2);

    // Get zlib compile flags
    uLong compile_flags = zlibCompileFlags();

    // Ensure all resources are freed and no memory leaks occur
    return 0;
}
