#include "zlib.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h> // Include this for INT32_MAX and ULONG_MAX

// Function to safely copy data from source to destination with size checking
void safe_memcpy(void* dest, const void* src, size_t dest_size, size_t src_size) {
    if (src_size > dest_size) {
        src_size = dest_size;
    }
    memcpy(dest, src, src_size);
}

// Function to safely cast size_t to int
int safe_cast_to_int(size_t value) {
    if (value > INT32_MAX) {
        return INT32_MAX;
    }
    return static_cast<int>(value);
}

// Function to safely cast size_t to uLong
uLong safe_cast_to_uLong(size_t value) {
    if (value > ULONG_MAX) {
        return ULONG_MAX;
    }
    return static_cast<uLong>(value);
}

// Function to safely cast size_t to z_off_t
z_off_t safe_cast_to_z_off_t(size_t value) {
    if (value > (z_off_t)ULONG_MAX) { // Use ULONG_MAX as a proxy for Z_OFF_MAX
        return (z_off_t)ULONG_MAX;
    }
    return static_cast<z_off_t>(value);
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure size is within reasonable limits to prevent excessive memory usage
    if (size > 1024 * 1024) {
        return 0;
    }

    // Initialize variables
    uLong crc1 = 0, crc2 = 0;
    z_off_t len2 = 0;
    int level = 0, strategy = 0;
    uLong sourceLen = 0, destLen = 0;
    Bytef *source = nullptr, *dest = nullptr;
    gzFile file = nullptr;
    int result = 0;

    // Allocate memory for source and dest buffers
    source = static_cast<Bytef*>(malloc(size));
    dest = static_cast<Bytef*>(malloc(size));
    if (!source || !dest) {
        free(source);
        free(dest);
        return 0;
    }

    // Copy fuzzer input to source buffer
    safe_memcpy(source, data, size, size);
    sourceLen = safe_cast_to_uLong(size);

    // Call crc32_combine
    crc1 = crc32(0L, Z_NULL, 0);
    crc2 = crc32(crc1, source, sourceLen);
    len2 = safe_cast_to_z_off_t(sourceLen);
    crc32_combine(crc1, crc2, len2);

    // Call uncompress2
    destLen = safe_cast_to_uLong(size);
    result = uncompress2(dest, &destLen, source, &sourceLen);
    if (result != Z_OK) {
        free(source);
        free(dest);
        return 0;
    }

    // Open a gzFile for writing
    file = gzopen("output_file", "wb");
    if (!file) {
        free(source);
        free(dest);
        return 0;
    }

    // Call gzsetparams
    level = safe_cast_to_int(data[0] % 10); // Compression level 0-9
    strategy = safe_cast_to_int(data[1] % 3); // Strategy 0-2
    gzsetparams(file, level, strategy);

    // Call gzwrite
    gzwrite(file, dest, static_cast<unsigned>(destLen));

    // Close the gzFile
    gzclose(file);

    // Free allocated memory
    free(source);
    free(dest);

    return 0;
}
