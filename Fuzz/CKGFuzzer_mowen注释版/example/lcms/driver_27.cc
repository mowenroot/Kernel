#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy a string with bounds checking
void safe_strncpy(char* dest, const char* src, size_t dest_size) {
    if (dest_size > 0) {
        strncpy(dest, src, dest_size - 1);
        dest[dest_size - 1] = '\0';
    }
}

// Function to safely convert a portion of the fuzz input to a string
void fuzz_input_to_string(const uint8_t* data, size_t size, char* dest, size_t dest_size) {
    if (size > dest_size - 1) {
        size = dest_size - 1;
    }
    memcpy(dest, data, size);
    dest[size] = '\0';
}

// Function to safely convert a portion of the fuzz input to a double
double fuzz_input_to_double(const uint8_t* data, size_t size) {
    char buffer[32];
    if (size > sizeof(buffer) - 1) {
        size = sizeof(buffer) - 1;
    }
    memcpy(buffer, data, size);
    buffer[size] = '\0';
    return strtod(buffer, NULL);
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < 32) {
        return 0;
    }

    // Initialize variables
    cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(NULL);
    cmsHANDLE hIT8 = cmsIT8Alloc(NULL);
    char languageCode[3] = {0};
    char countryCode[3] = {0};
    wchar_t profileInfoBuffer[256] = {0};
    char sheetType[64] = {0};
    char propertyKey[64] = {0};
    char propertyValue[64] = {0};
    char patch[64] = {0};
    char sample[64] = {0};
    double value = 0.0;

    // Extract data from fuzz input
    fuzz_input_to_string(data, 2, languageCode, sizeof(languageCode));
    fuzz_input_to_string(data + 2, 2, countryCode, sizeof(countryCode));
    fuzz_input_to_string(data + 4, 63, sheetType, sizeof(sheetType));
    fuzz_input_to_string(data + 67, 63, propertyKey, sizeof(propertyKey));
    fuzz_input_to_string(data + 130, 63, propertyValue, sizeof(propertyValue));
    fuzz_input_to_string(data + 193, 63, patch, sizeof(patch));
    fuzz_input_to_string(data + 256, 63, sample, sizeof(sample));
    value = fuzz_input_to_double(data + 319, size - 319);

    // Call cmsIsCLUT
    cmsBool isCLUT = cmsIsCLUT(hProfile, 1, LCMS_USED_AS_INPUT);
    if (isCLUT == FALSE) {
        // Handle error
    }

    // Call cmsIT8SetSheetType
    cmsBool setSheetType = cmsIT8SetSheetType(hIT8, sheetType);
    if (setSheetType == FALSE) {
        // Handle error
    }

    // Call cmsIT8SetPropertyUncooked
    cmsBool setProperty = cmsIT8SetPropertyUncooked(hIT8, propertyKey, propertyValue);
    if (setProperty == FALSE) {
        // Handle error
    }

    // Call cmsIT8SetDataDbl
    cmsBool setDataDbl = cmsIT8SetDataDbl(hIT8, patch, sample, value);
    if (setDataDbl == FALSE) {
        // Handle error
    }

    // Call cmsGetProfileInfo
    cmsUInt32Number profileInfoSize = cmsGetProfileInfo(hProfile, cmsInfoDescription, languageCode, countryCode, profileInfoBuffer, sizeof(profileInfoBuffer) / sizeof(wchar_t));
    if (profileInfoSize == 0) {
        // Handle error
    }

    // Clean up resources
    cmsIT8Free(hIT8);
    cmsCloseProfile(hProfile);

    return 0;
}
