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

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is valid
    if (size < 2) {
        return 0;
    }

    // Convert fuzz input to a string
    char* codecName = fuzzInputToString(data, size - 2);
    if (codecName == NULL) {
        return 0;
    }

    // Extract the scheme from the fuzz input
    uint16_t scheme = (uint16_t)((data[size - 2] << 8) | data[size - 1]);

    // Initialize variables
    TIFFCodec* codec = NULL;
    TIFFCodec* registeredCodec = NULL;
    TIFFCodec* configuredCodecs = NULL;
    int isConfigured = 0;

    // Register the codec
    registeredCodec = TIFFRegisterCODEC(scheme, codecName, NULL);
    if (registeredCodec == NULL) {
        safeFree(codecName);
        return 0;
    }

    // Check if the codec is configured
    isConfigured = TIFFIsCODECConfigured(scheme);

    // Find the codec
    codec = (TIFFCodec*)TIFFFindCODEC(scheme);

    // Get configured codecs
    configuredCodecs = TIFFGetConfiguredCODECs();
    if (configuredCodecs != NULL) {
        // Unregister the codec
        TIFFUnRegisterCODEC(registeredCodec);
        safeFree(configuredCodecs);
    }

    // Set a custom error handler
    TIFFErrorHandler oldHandler = TIFFSetErrorHandler(NULL);

    // Restore the old error handler
    TIFFSetErrorHandler(oldHandler);

    // Free allocated resources
    safeFree(codecName);

    return 0;
}
