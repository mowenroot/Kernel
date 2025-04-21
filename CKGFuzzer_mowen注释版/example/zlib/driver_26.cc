#include "zlib.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <wchar.h>
#include <locale.h>

// Function to convert uint8_t array to wchar_t string
wchar_t* convertToWChar(const uint8_t* data, size_t size) {
    wchar_t* wstr = (wchar_t*)malloc((size + 1) * sizeof(wchar_t));
    if (!wstr) return nullptr;
    for (size_t i = 0; i < size; ++i) {
        wstr[i] = (wchar_t)data[i];
    }
    wstr[size] = L'\0';
    return wstr;
}

// Function to free the allocated wchar_t string
void freeWChar(wchar_t* wstr) {
    free(wstr);
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for all operations
    if (size < 10) return 0;

    // Initialize variables
    gzFile file = nullptr;
    wchar_t* wpath = nullptr;
    char* path = nullptr;
    int level = data[0];
    int strategy = data[1];
    int bits = data[2];
    int value = data[3];
    unsigned long crc = 0;

    // Convert the first part of the input to a wchar_t string for gzopen_w
    wpath = convertToWChar(data + 4, size - 4);
    if (!wpath) return 0;

    // Convert wchar_t path to char path
    size_t path_len = wcslen(wpath) + 1;
    path = (char*)malloc(path_len * sizeof(char));
    if (!path) {
        freeWChar(wpath);
        return 0;
    }
    wcstombs(path, wpath, path_len);

    // Open the file with gzopen
    file = gzopen(path, "wb");
    if (!file) {
        free(path);
        freeWChar(wpath);
        return 0;
    }

    // Set compression parameters with gzsetparams
    if (gzsetparams(file, level, strategy) != Z_OK) {
        gzclose(file);
        free(path);
        freeWChar(wpath);
        return 0;
    }

    // Prime the inflate state with inflatePrime
    z_stream strm;
    memset(&strm, 0, sizeof(strm));
    if (inflatePrime(&strm, bits, value) != Z_OK) {
        gzclose(file);
        free(path);
        freeWChar(wpath);
        return 0;
    }

    // Compute CRC-32 checksum with crc32_z
    crc = crc32_z(crc, data, size);

    // Close the file with gzclose
    if (gzclose(file) != Z_OK) {
        free(path);
        freeWChar(wpath);
        return 0;
    }

    // Free allocated resources
    free(path);
    freeWChar(wpath);

    return 0;
}
