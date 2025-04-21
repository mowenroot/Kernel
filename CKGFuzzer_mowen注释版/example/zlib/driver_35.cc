#include "zlib.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>  // Include this header for 'stderr' and 'tmpfile'

// Function to safely allocate memory
void* safe_malloc(size_t size) {
    void* ptr = malloc(size);
    if (!ptr) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    return ptr;
}

// Function to safely free memory
void safe_free(void* ptr) {
    if (ptr) {
        free(ptr);
    }
}

// Function to safely copy data
void safe_memcpy(void* dest, const void* src, size_t n) {
    if (dest && src && n > 0) {
        memcpy(dest, src, n);
    }
}

// Function to safely set memory
void safe_memset(void* s, int c, size_t n) {
    if (s && n > 0) {
        memset(s, c, n);
    }
}

// Function to safely cast data
template <typename T>
T safe_cast(const uint8_t* data, size_t size, size_t offset) {
    if (offset + sizeof(T) <= size) {
        return *reinterpret_cast<const T*>(data + offset);
    }
    return T();
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for our operations
    if (size < 10) {
        return 0;
    }

    // Initialize variables
    z_stream strm;
    safe_memset(&strm, 0, sizeof(strm));
    gzFile file = nullptr;
    char* buf = nullptr;
    int result = 0;

    // Allocate memory for the buffer
    buf = static_cast<char*>(safe_malloc(size));

    // Initialize the zlib stream
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;

    // Initialize the gzFile
    FILE* tmp = tmpfile();  // Create a temporary file
    if (!tmp) {
        safe_free(buf);
        return 0;
    }
    file = gzdopen(fileno(tmp), "rb");
    if (!file) {
        safe_free(buf);
        fclose(tmp);  // Close the temporary file
        return 0;
    }

    // Reset the inflate state
    result = inflateReset(&strm);
    if (result != Z_OK) {
        gzclose(file);
        safe_free(buf);
        fclose(tmp);  // Close the temporary file
        return 0;
    }

    // Check if the file is in direct mode
    int direct = gzdirect(file);
    if (direct < 0) {
        gzclose(file);
        safe_free(buf);
        fclose(tmp);  // Close the temporary file
        return 0;
    }

    // Read a line from the file
    char* line = gzgets(file, buf, size);
    if (!line) {
        gzclose(file);
        safe_free(buf);
        fclose(tmp);  // Close the temporary file
        return 0;
    }

    // Push a character back onto the input stream
    int pushed_char = gzungetc(safe_cast<int>(data, size, 0), file);
    if (pushed_char < 0) {
        gzclose(file);
        safe_free(buf);
        fclose(tmp);  // Close the temporary file
        return 0;
    }

    // Read data from the file
    z_size_t read_size = gzfread(buf, 1, size, file);
    if (read_size == 0) {
        gzclose(file);
        safe_free(buf);
        fclose(tmp);  // Close the temporary file
        return 0;
    }

    // Clean up
    gzclose(file);
    safe_free(buf);
    fclose(tmp);  // Close the temporary file

    return 0;
}
