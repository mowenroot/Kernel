#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to convert fuzz input to a string
char* fuzzInputToString(const uint8_t* data, size_t size) {
    char* str = (char*)malloc(size + 1);
    if (str == NULL) {
        return NULL;
    }
    memcpy(str, data, size);
    str[size] = '\0';
    return str;
}

// Function to free allocated memory
void safeFree(void* ptr) {
    if (ptr != NULL) {
        free(ptr);
    }
}

// Function to check if a pointer is NULL and handle errors
void checkNullPointer(void* ptr, const char* message) {
    if (ptr == NULL) {
        fprintf(stderr, "Error: %s\n", message);
        exit(1);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is at least 2 bytes for scheme and name
    if (size < 2) {
        return 0;
    }

    // Extract the scheme and name from the fuzz input
    uint16_t scheme = (uint16_t)data[0];
    char* name = fuzzInputToString(data + 1, size - 1);
    checkNullPointer(name, "Failed to allocate memory for codec name");

    // Register the codec
    TIFFCodec* codec = TIFFRegisterCODEC(scheme, name, NULL);
    if (codec != NULL) {
        // Check if the codec is configured
        int isConfigured = TIFFIsCODECConfigured(scheme);

        // Find the codec
        const TIFFCodec* foundCodec = TIFFFindCODEC(scheme);

        // Get the list of configured codecs
        TIFFCodec* configuredCodecs = TIFFGetConfiguredCODECs();
        if (configuredCodecs != NULL) {
            // Iterate through the list of configured codecs
            for (int i = 0; configuredCodecs[i].name != NULL; i++) {
                // Unregister the codec
                TIFFUnRegisterCODEC(&configuredCodecs[i]);
            }
            _TIFFfree(configuredCodecs);
        }

        // Unregister the codec
        TIFFUnRegisterCODEC(codec);
    }

    // Free allocated memory
    safeFree(name);

    return 0;
}
