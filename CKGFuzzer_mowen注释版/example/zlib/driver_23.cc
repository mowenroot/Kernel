#include <zlib.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <cstdio> // Include this header for FILE and tmpfile

// Function to create a gzFile from the fuzzer input data
gzFile create_gzfile(const uint8_t *data, size_t size) {
    // Create a temporary file and write the fuzzer input data to it
    FILE *temp_file = tmpfile();
    if (!temp_file) {
        return NULL;
    }
    fwrite(data, 1, size, temp_file);
    rewind(temp_file);

    // Open the temporary file as a gzFile for reading
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

    // Test gzfread
    z_size_t bytes_read = gzfread(buffer, 1, buffer_size, gz_file);
    if (bytes_read == 0 && gzerror(gz_file, NULL) != Z_OK) {
        free_gzfile(gz_file);
        return 0;
    }

    // Test gzgets
    char line_buffer[buffer_size];
    memset(line_buffer, 0, buffer_size);
    char *result = gzgets(gz_file, line_buffer, buffer_size);
    if (!result && gzerror(gz_file, NULL) != Z_OK) {
        free_gzfile(gz_file);
        return 0;
    }

    // Test gzread
    memset(buffer, 0, buffer_size);
    int read_result = gzread(gz_file, buffer, buffer_size);
    if (read_result < 0 && gzerror(gz_file, NULL) != Z_OK) {
        free_gzfile(gz_file);
        return 0;
    }

    // Test gzflush (note: gzflush is for writing, so we simulate a write operation)
    // Since we are reading, we can't directly test gzflush, but we can ensure it compiles and links correctly
    // This is a placeholder for a write operation, which is not applicable here
    // int flush_result = gzflush(gz_file, Z_SYNC_FLUSH);
    // if (flush_result != Z_OK && gzerror(gz_file, NULL) != Z_OK) {
    //     free_gzfile(gz_file);
    //     return 0;
    // }

    // Test gzclose_r
    int close_result = gzclose_r(gz_file);
    if (close_result != Z_OK) {
        return 0;
    }

    return 0;
}
