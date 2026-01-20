#include <zlib.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <cstdio>  // Include this header for FILE and tmpfile

// Function to create a gzFile from the fuzzer input data
gzFile create_gzfile(const uint8_t *data, size_t size) {
    // Create a temporary file and write the fuzzer input data to it
    FILE *temp_file = tmpfile();
    if (!temp_file) {
        return NULL;
    }
    fwrite(data, 1, size, temp_file);
    rewind(temp_file);

    // Open the temporary file as a gzFile
    gzFile gz_file = gzdopen(fileno(temp_file), "rb");
    if (!gz_file) {
        fclose(temp_file);
        return NULL;
    }

    return gz_file;
}

// Function to free the gzFile and associated resources
void free_gzfile(gzFile gz_file) {
    if (gz_file) {
        gzclose_r(gz_file);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is within a reasonable limit to prevent excessive memory usage
    if (size > 1024 * 1024) {
        return 0;
    }

    // Create a gzFile from the fuzzer input data
    gzFile gz_file = create_gzfile(data, size);
    if (!gz_file) {
        return 0;
    }

    // Buffer for reading data
    const size_t buffer_size = 1024;
    uint8_t buffer[buffer_size];
    memset(buffer, 0, buffer_size);

    // Read data using gzread
    int bytes_read = gzread(gz_file, buffer, buffer_size - 1);
    if (bytes_read < 0) {
        int errnum;
        const char *error_msg = gzerror(gz_file, &errnum);
        // Handle error (e.g., log or assert)
        free_gzfile(gz_file);
        return 0;
    }

    // Read a line using gzgets
    char line_buffer[buffer_size];
    char *line = gzgets(gz_file, line_buffer, buffer_size - 1);
    if (!line) {
        int errnum;
        const char *error_msg = gzerror(gz_file, &errnum);
        // Handle error (e.g., log or assert)
        free_gzfile(gz_file);
        return 0;
    }

    // Check if the file is in direct mode using gzdirect
    int direct_mode = gzdirect(gz_file);
    if (direct_mode < 0) {
        int errnum;
        const char *error_msg = gzerror(gz_file, &errnum);
        // Handle error (e.g., log or assert)
        free_gzfile(gz_file);
        return 0;
    }

    // Free the gzFile and associated resources
    free_gzfile(gz_file);

    return 0;
}
