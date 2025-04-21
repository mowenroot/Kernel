#include "zlib.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h> // Include this header for O_RDWR and O_CREAT
#include <unistd.h> // Include this header for close()

// Function to safely convert fuzz input to a string
const char* SafeStringFromData(const uint8_t* data, size_t size) {
    static char buffer[256];
    size_t len = size < 255 ? size : 255;
    memcpy(buffer, data, len);
    buffer[len] = '\0';
    return buffer;
}

// Function to safely convert fuzz input to an integer
int SafeIntFromData(const uint8_t* data, size_t size) {
    if (size == 0) return 0;
    return static_cast<int>(data[0]);
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for our operations
    if (size < 10) return 0;

    // Initialize variables
    gzFile file = nullptr;
    int fd = -1;
    int result = 0;

    // Open a file descriptor for gzdopen
    fd = open("input_file", O_RDWR | O_CREAT, 0644);
    if (fd == -1) {
        return 0;
    }

    // Create a gzFile handle from the file descriptor
    const char* mode = SafeStringFromData(data, 2); // Use first 2 bytes as mode
    file = gzdopen(fd, mode);
    if (file == nullptr) {
        close(fd);
        return 0;
    }

    // Set the buffer size for the gzFile stream
    unsigned bufferSize = static_cast<unsigned>(SafeIntFromData(data + 2, 1)); // Use next byte as buffer size
    result = gzbuffer(file, bufferSize);
    if (result != 0) {
        gzclose(file);
        return 0;
    }

    // Check if the file is in transparent mode
    int isDirect = gzdirect(file);
    if (isDirect) {
        // Handle transparent mode operations
    }

    // Clear any error or end-of-file flags
    gzclearerr(file);

    // Check if the end of the file has been reached
    int isEOF = gzeof(file);
    if (isEOF) {
        // Handle end-of-file operations
    }

    // Close the gzFile
    result = gzclose(file);
    if (result != Z_OK) {
        return 0;
    }

    // Return 0 to indicate successful execution
    return 0;
}
