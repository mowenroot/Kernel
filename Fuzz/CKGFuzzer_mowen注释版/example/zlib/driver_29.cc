#include "zlib.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>
#include <cstdio>  // Include for stderr

// Function to handle memory allocation failures
void handle_memory_failure() {
    fprintf(stderr, "Memory allocation failed\n");
    exit(1);
}

// Function to safely allocate memory
template <typename T>
T* safe_malloc(size_t size) {
    T* ptr = static_cast<T*>(malloc(size));
    if (!ptr) {
        handle_memory_failure();
    }
    return ptr;
}

// Function to safely allocate memory using new
template <typename T>
T* safe_new() {
    T* ptr = new T();
    if (!ptr) {
        handle_memory_failure();
    }
    return ptr;
}

// Function to safely allocate memory for an array using new
template <typename T>
T* safe_new_array(size_t size) {
    T* ptr = new T[size];
    if (!ptr) {
        handle_memory_failure();
    }
    return ptr;
}

// Function to read data from gzFile for inflateBack
unsigned int read_func(void* in_desc, unsigned char** in_ptr) {
    gzFile gz_file = static_cast<gzFile>(in_desc);
    int bytes_read = gzread(gz_file, *in_ptr, 1);
    if (bytes_read < 0) {
        return 0; // Indicate end of input
    }
    return bytes_read;
}

// Function to write data for inflateBack
int write_func(void* out_desc, unsigned char* out_ptr, unsigned len) {
    memcpy(out_desc, out_ptr, len);
    return len;
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is within a reasonable limit to prevent excessive memory usage
    if (size > 1024 * 1024) {
        return 0;
    }

    // Initialize variables
    gzFile gz_file = nullptr;
    z_stream strm;
    int ret = Z_OK;
    int errnum = Z_OK;
    unsigned long crc = 0;

    // Allocate memory for the input buffer
    std::unique_ptr<char[]> input_buffer(safe_new_array<char>(size + 1));
    memcpy(input_buffer.get(), data, size);
    input_buffer[size] = '\0'; // Null-terminate the string

    // Open a gzFile for writing
    gz_file = gzopen("output_file", "wb");
    if (!gz_file) {
        fprintf(stderr, "Failed to open gzFile for writing\n");
        return 0;
    }

    // Write the input buffer to the gzFile
    ret = gzputs(gz_file, input_buffer.get());
    if (ret < 0) {
        fprintf(stderr, "gzputs failed\n");
        gzclose(gz_file);
        return 0;
    }

    // Set compression parameters
    ret = gzsetparams(gz_file, Z_DEFAULT_COMPRESSION, Z_DEFAULT_STRATEGY);
    if (ret != Z_OK) {
        fprintf(stderr, "gzsetparams failed\n");
        gzclose(gz_file);
        return 0;
    }

    // Close the gzFile
    ret = gzclose(gz_file);
    if (ret != Z_OK) {
        fprintf(stderr, "gzclose failed\n");
        return 0;
    }

    // Reopen the gzFile for reading
    gz_file = gzopen("output_file", "rb");
    if (!gz_file) {
        fprintf(stderr, "Failed to open gzFile for reading\n");
        return 0;
    }

    // Initialize the z_stream structure for inflateBack
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;

    ret = inflateInit2(&strm, 15 + 32); // 15 + 32 to enable gzip decoding
    if (ret != Z_OK) {
        fprintf(stderr, "inflateInit2 failed\n");
        gzclose(gz_file);
        return 0;
    }

    // Allocate memory for the output buffer
    std::unique_ptr<char[]> output_buffer(safe_new_array<char>(size * 2)); // Assume worst-case expansion
    strm.avail_out = size * 2;
    strm.next_out = reinterpret_cast<Bytef*>(output_buffer.get());

    // Use inflateBack to decompress the data
    ret = inflateBack(
        &strm,
        read_func,
        gz_file,
        write_func,
        output_buffer.get()
    );

    if (ret != Z_STREAM_END) {
        fprintf(stderr, "inflateBack failed\n");
        inflateEnd(&strm);
        gzclose(gz_file);
        return 0;
    }

    // Calculate the CRC-32 checksum of the decompressed data
    crc = crc32_z(crc, reinterpret_cast<const unsigned char*>(output_buffer.get()), strm.total_out);

    // Check for errors using gzerror
    const char* error_msg = gzerror(gz_file, &errnum);
    if (errnum != Z_OK) {
        fprintf(stderr, "gzerror: %s\n", error_msg);
    }

    // Clean up
    inflateEnd(&strm);
    gzclose(gz_file);

    return 0;
}
