#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sstream> // Include for std::istringstream

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

    // Extract the scheme from the input
    uint16_t scheme = (uint16_t)((data[size - 2] << 8) | data[size - 1]);

    // Initialize variables
    TIFFCodec* codec = NULL;
    const TIFFCodec* foundCodec = NULL;
    TIFFCodec* configuredCodecs = NULL;
    const TIFFField* foundField = NULL;

    // Register the codec
    codec = TIFFRegisterCODEC(scheme, codecName, NULL);
    if (codec == NULL) {
        safeFree(codecName);
        return 0;
    }

    // Check if the codec is configured
    int isConfigured = TIFFIsCODECConfigured(scheme);

    // Find the codec
    foundCodec = TIFFFindCODEC(scheme);

    // Get configured codecs
    configuredCodecs = TIFFGetConfiguredCODECs();
    if (configuredCodecs != NULL) {
        // Unregister the codec
        TIFFUnRegisterCODEC(codec);

        // Free the configured codecs list
        safeFree(configuredCodecs);
    }

    // Find a field (example usage, assuming a TIFF object is needed)
    // Corrected the call to TIFFStreamOpen to match the expected signature
    std::istringstream iss(codecName);
    TIFF* tif = TIFFStreamOpen("MemTIFF", &iss);
    if (tif != NULL) {
        foundField = TIFFFindField(tif, TIFFTAG_IMAGEWIDTH, TIFF_LONG);
        TIFFClose(tif);
    }

    // Free allocated resources
    safeFree(codecName);

    return 0;
}
