#include "zlib.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely convert fuzz input to an integer
int safe_int_from_data(const uint8_t *data, size_t size, size_t *index) {
    if (*index + sizeof(int) > size) {
        return 0; // Default value if not enough data
    }
    int value = *reinterpret_cast<const int*>(data + *index);
    *index += sizeof(int);
    return value;
}

// Function to safely convert fuzz input to an unsigned integer
unsigned int safe_uint_from_data(const uint8_t *data, size_t size, size_t *index) {
    if (*index + sizeof(unsigned int) > size) {
        return 0; // Default value if not enough data
    }
    unsigned int value = *reinterpret_cast<const unsigned int*>(data + *index);
    *index += sizeof(unsigned int);
    return value;
}

// Function to safely convert fuzz input to a z_off_t
z_off_t safe_z_off_t_from_data(const uint8_t *data, size_t size, size_t *index) {
    if (*index + sizeof(z_off_t) > size) {
        return 0; // Default value if not enough data
    }
    z_off_t value = *reinterpret_cast<const z_off_t*>(data + *index);
    *index += sizeof(z_off_t);
    return value;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < sizeof(int) * 3 + sizeof(z_off_t) + sizeof(unsigned int)) {
        return 0;
    }

    // Initialize variables
    size_t index = 0;
    int level = safe_int_from_data(data, size, &index);
    int strategy = safe_int_from_data(data, size, &index);
    z_off_t offset = safe_z_off_t_from_data(data, size, &index);
    unsigned int buffer_size = safe_uint_from_data(data, size, &index);

    // Open a gzFile for writing
    gzFile file = gzopen("output_file", "wb");
    if (file == nullptr) {
        return 0; // Failed to open file
    }

    // Set buffer size
    if (gzbuffer(file, buffer_size) != 0) {
        gzclose(file);
        return 0; // Failed to set buffer size
    }

    // Set compression parameters
    if (gzsetparams(file, level, strategy) != Z_OK) {
        gzclose(file);
        return 0; // Failed to set compression parameters
    }

    // Seek to a specified offset
    if (gzseek(file, offset, SEEK_SET) == -1) {
        gzclose(file);
        return 0; // Failed to seek
    }

    // Rewind the file pointer
    if (gzrewind(file) != 0) {
        gzclose(file);
        return 0; // Failed to rewind
    }

    // Clear any errors
    gzclearerr(file);

    // Close the file
    gzclose(file);

    return 0;
}
