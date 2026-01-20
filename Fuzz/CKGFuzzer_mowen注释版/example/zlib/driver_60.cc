#include <zlib.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely convert uint8_t array to a null-terminated string
char* safe_strndup(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    char* str = (char*)malloc(size + 1);
    if (!str) return nullptr;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely convert uint8_t array to a wide character string
wchar_t* safe_wcsndup(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    wchar_t* wstr = (wchar_t*)malloc((size + 1) * sizeof(wchar_t));
    if (!wstr) return nullptr;
    for (size_t i = 0; i < size; ++i) {
        wstr[i] = (wchar_t)data[i];
    }
    wstr[size] = L'\0';
    return wstr;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is reasonable to prevent excessive memory usage
    if (size < 1 || size > 1024) return 0;

    // Create a buffer for reading and writing
    const size_t buffer_size = 1024;
    uint8_t read_buffer[buffer_size];
    uint8_t write_buffer[buffer_size];

    // Safely convert the input data to a file name
    char* file_name = safe_strndup(data, size);
    if (!file_name) return 0;

    // Open the file for writing
    gzFile gz_write_file = gzopen(file_name, "wb");
    if (!gz_write_file) {
        free(file_name);
        return 0;
    }

    // Write some data to the file
    memcpy(write_buffer, data, size);
    int bytes_written = gzwrite(gz_write_file, write_buffer, size);
    if (bytes_written != static_cast<int>(size)) {
        gzclose(gz_write_file);
        free(file_name);
        return 0;
    }

    // Flush the file to ensure data is written
    int flush_result = gzflush(gz_write_file, Z_FINISH);
    if (flush_result != Z_OK) {
        gzclose(gz_write_file);
        free(file_name);
        return 0;
    }

    // Close the file after writing
    int close_result = gzclose(gz_write_file);
    if (close_result != Z_OK) {
        free(file_name);
        return 0;
    }

    // Open the file for reading
    gzFile gz_read_file = gzopen(file_name, "rb");
    if (!gz_read_file) {
        free(file_name);
        return 0;
    }

    // Read data from the file
    int bytes_read = gzread(gz_read_file, read_buffer, buffer_size);
    if (bytes_read < 0) {
        gzclose(gz_read_file);
        free(file_name);
        return 0;
    }

    // Close the file after reading
    close_result = gzclose(gz_read_file);
    if (close_result != Z_OK) {
        free(file_name);
        return 0;
    }

    // Clean up
    free(file_name);
    return 0;
}
