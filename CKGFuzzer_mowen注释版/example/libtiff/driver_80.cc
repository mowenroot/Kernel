#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <sstream> // Include sstream for std::istringstream

// Function to safely allocate memory
void* safe_malloc(size_t size) {
    void* ptr = malloc(size);
    if (!ptr) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    return ptr;
}

// Function to safely copy a string
char* safe_strndup(const char* str, size_t n) {
    char* new_str = (char*)safe_malloc(n + 1);
    strncpy(new_str, str, n);
    new_str[n] = '\0';
    return new_str;
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < 1) {
        return 0;
    }

    // Create a TIFF object in memory using std::istringstream
    std::istringstream s(std::string(reinterpret_cast<const char*>(data), size));
    TIFF* tif = TIFFStreamOpen("mem", &s);
    if (!tif) {
        return 0;
    }

    // Extract the file descriptor and file name
    int fd = TIFFFileno(tif);
    const char* filename = TIFFFileName(tif);

    // Set a new file name derived from the fuzz input
    char* new_filename = safe_strndup((const char*)data, size);
    const char* old_filename = TIFFSetFileName(tif, new_filename);

    // Set a new file descriptor derived from the fuzz input
    int new_fd = (int)(data[0]);
    int old_fd = TIFFSetFileno(tif, new_fd);

    // Set client info derived from the fuzz input
    const char* client_name = "fuzz_client";
    void* client_data = (void*)(data + 1);
    TIFFSetClientInfo(tif, client_data, client_name);

    // Retrieve the client info
    void* retrieved_client_data = TIFFGetClientInfo(tif, client_name);

    // Clean up
    TIFFClose(tif);
    free((void*)old_filename);
    free((void*)new_filename);

    return 0;
}
