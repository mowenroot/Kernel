#include <zlib.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>  // Include this header for FILE and tmpfile

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

    return gz_file;
}

// Function to close and clean up a gzFile
void close_gzfile(gzFile gz_file) {
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

    // Create a gzFile from the input data
    gzFile gz_file = create_gzfile_from_buffer(data, size);
    if (!gz_file) {
        return 0;
    }

    // Buffer for reading data
    uint8_t read_buffer[1024];
    memset(read_buffer, 0, sizeof(read_buffer));

    // Read data from the gzFile
    z_size_t bytes_read = gzfread(read_buffer, 1, sizeof(read_buffer), gz_file);
    if (bytes_read == 0) {
        int errnum;
        const char *error_msg = gzerror(gz_file, &errnum);
        if (errnum != Z_OK) {
            // Handle the error
            gzclearerr(gz_file);
        }
    }

    // Write data back to the gzFile (simulate writing)
    z_size_t bytes_written = gzfwrite(read_buffer, 1, bytes_read, gz_file);
    if (bytes_written == 0) {
        int errnum;
        const char *error_msg = gzerror(gz_file, &errnum);
        if (errnum != Z_OK) {
            // Handle the error
            gzclearerr(gz_file);
        }
    }

    // Close the gzFile and clean up
    close_gzfile(gz_file);

    return 0;
}
