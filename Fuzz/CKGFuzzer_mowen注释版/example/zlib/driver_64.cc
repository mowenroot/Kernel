#include "zlib.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy a string from fuzz input
char* safe_strndup(const uint8_t* data, size_t size) {
    if (size == 0) return nullptr;
    char* str = (char*)malloc(size + 1);
    if (!str) return nullptr;
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to safely extract an integer from fuzz input
int safe_extract_int(const uint8_t* data, size_t size, size_t& offset) {
    if (offset + sizeof(int) > size) return 0;
    int value = *(int*)(data + offset);
    offset += sizeof(int);
    return value;
}

// Function to safely extract a byte from fuzz input
uint8_t safe_extract_byte(const uint8_t* data, size_t size, size_t& offset) {
    if (offset >= size) return 0;
    return data[offset++];
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < sizeof(int) * 3 + 1) return 0;

    // Extract parameters from fuzz input
    size_t offset = 0;
    int level = safe_extract_int(data, size, offset);
    int strategy = safe_extract_int(data, size, offset);
    int push_char = safe_extract_byte(data, size, offset);

    // Open a gzFile for reading
    char* mode = safe_strndup(data + offset, size - offset);
    if (!mode) return 0;
    gzFile file = gzopen("input_file", mode);
    free(mode);
    if (!file) return 0;

    // Initialize zlib stream for deflate
    z_stream strm;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;
    int ret = deflateInit(&strm, Z_DEFAULT_COMPRESSION);
    if (ret != Z_OK) {
        gzclose(file);
        return 0;
    }

    // Adjust deflate parameters
    ret = deflateParams(&strm, level, strategy);
    if (ret != Z_OK) {
        deflateEnd(&strm);
        gzclose(file);
        return 0;
    }

    // Push a character back into the gzFile stream
    ret = gzungetc(push_char, file);
    if (ret == -1) {
        deflateEnd(&strm);
        gzclose(file);
        return 0;
    }

    // Compute CRC32 checksum of the input data
    unsigned long crc = crc32(0L, Z_NULL, 0);
    crc = crc32(crc, data, size);

    // Reset the inflate state while keeping the dictionary
    ret = inflateResetKeep(&strm);
    if (ret != Z_OK) {
        deflateEnd(&strm);
        gzclose(file);
        return 0;
    }

    // Clean up resources
    deflateEnd(&strm);
    gzclose(file);

    return 0;
}
