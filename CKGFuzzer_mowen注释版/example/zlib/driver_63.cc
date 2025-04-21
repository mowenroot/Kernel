#include <zlib.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <iostream>
#include <memory>

// Function to create a gzFile from a buffer
gzFile create_gzfile_from_buffer(const uint8_t *data, size_t size) {
    // Create a temporary file and write the data to it
    FILE *temp_file = tmpfile();
    if (!temp_file) {
        return nullptr;
    }
    fwrite(data, 1, size, temp_file);
    rewind(temp_file);

    // Open the temporary file as a gzFile
    gzFile gz_file = gzdopen(fileno(temp_file), "rb");
    if (!gz_file) {
        fclose(temp_file);
        return nullptr;
    }

    // Return the gzFile
    return gz_file;
}

// Function to close and clean up the gzFile
void close_gzfile(gzFile gz_file) {
    if (gz_file) {
        gzclose(gz_file);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is within a reasonable limit to prevent excessive memory usage
    if (size > 1024 * 1024) {
        return 0;
    }

    // Create a gzFile from the input data
    gzFile gz_file = create_gzfile_from_buffer(data, size);
    if (!gz_file) {
        return 0;
    }

    // Initialize variables for API calls
    z_off_t offset = 0;
    int errnum = 0;
    const char *error_msg = nullptr;

    // Call gzseek with an offset derived from the input data
    offset = gzseek(gz_file, static_cast<z_off_t>(data[0]), SEEK_SET);
    if (offset == -1) {
        // Handle error
        std::cerr << "gzseek failed" << std::endl;
    }

    // Call gzrewind
    if (gzrewind(gz_file) == -1) {
        // Handle error
        std::cerr << "gzrewind failed" << std::endl;
    }

    // Call gzerror to get the error message and number
    error_msg = gzerror(gz_file, &errnum);
    if (errnum != Z_OK) {
        // Handle error
        std::cerr << "gzerror: " << error_msg << " (error code: " << errnum << ")" << std::endl;
    }

    // Call gzoffset to get the current offset
    offset = gzoffset(gz_file);
    if (offset == -1) {
        // Handle error
        std::cerr << "gzoffset failed" << std::endl;
    }

    // Call gztell to get the current file position
    offset = gztell(gz_file);
    if (offset == -1) {
        // Handle error
        std::cerr << "gztell failed" << std::endl;
    }

    // Close the gzFile and clean up
    close_gzfile(gz_file);

    return 0;
}
