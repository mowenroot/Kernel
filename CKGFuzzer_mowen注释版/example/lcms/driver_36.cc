#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>  // Added for snprintf

// Function to safely convert a byte array to a double
double safe_byte_to_double(const uint8_t* data, size_t size) {
    if (size < sizeof(double)) {
        return 0.0;
    }
    double value;
    memcpy(&value, data, sizeof(double));
    return value;
}

// Function to safely convert a byte array to an integer
int safe_byte_to_int(const uint8_t* data, size_t size) {
    if (size < sizeof(int)) {
        return 0;
    }
    int value;
    memcpy(&value, data, sizeof(int));
    return value;
}

// Function to safely convert a byte array to a string
const char* safe_byte_to_string(const uint8_t* data, size_t size, char* buffer, size_t buffer_size) {
    if (size > buffer_size - 1) {
        size = buffer_size - 1;
    }
    memcpy(buffer, data, size);
    buffer[size] = '\0';
    return buffer;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < 100) {
        return 0;
    }

    // Initialize variables
    cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(NULL);
    cmsHANDLE hIT8 = cmsIT8Alloc(NULL);
    cmsMLU* mlu = cmsMLUalloc(NULL, 1);
    cmsCIEXYZ BlackPoint;
    wchar_t buffer[256];
    char langCode[3], countryCode[3];

    // Derive inputs from fuzz data
    int row = safe_byte_to_int(data, size);
    int col = safe_byte_to_int(data + sizeof(int), size - sizeof(int));
    double value = safe_byte_to_double(data + 2 * sizeof(int), size - 2 * sizeof(int));
    safe_byte_to_string(data + 3 * sizeof(int), size - 3 * sizeof(int), langCode, 3);
    safe_byte_to_string(data + 3 * sizeof(int) + 3, size - 3 * sizeof(int) - 3, countryCode, 3);

    // Corrected call to cmsIT8SetDataDbl
    char rowStr[16];
    char colStr[16];
    snprintf(rowStr, sizeof(rowStr), "%d", row);  // Convert row to string
    snprintf(colStr, sizeof(colStr), "%d", col);  // Convert col to string
    cmsIT8SetDataDbl(hIT8, rowStr, colStr, value);

    // Call APIs
    cmsIT8GetDataRowColDbl(hIT8, row, col);
    cmsIsMatrixShaper(hProfile);
    cmsDetectBlackPoint(&BlackPoint, hProfile, INTENT_PERCEPTUAL, 0);
    cmsGetProfileInfo(hProfile, cmsInfoDescription, langCode, countryCode, buffer, sizeof(buffer));

    // Free resources
    cmsMLUfree(mlu);
    cmsIT8Free(hIT8);
    cmsCloseProfile(hProfile);

    return 0;
}
