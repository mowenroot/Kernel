#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy a string from fuzz input
char* SafeStrndup(const uint8_t* data, size_t size, size_t max_len) {
    size_t len = strnlen(reinterpret_cast<const char*>(data), size);
    if (len > max_len) len = max_len;
    char* str = static_cast<char*>(malloc(len + 1));
    if (str) {
        memcpy(str, data, len);
        str[len] = '\0';
    }
    return str;
}

// Function to safely convert fuzz input to a double
double SafeStrtod(const uint8_t* data, size_t size) {
    char* endptr;
    char* str = SafeStrndup(data, size, size);
    if (!str) return 0.0;
    double val = strtod(str, &endptr);
    free(str);
    return val;
}

// Function to safely convert fuzz input to an integer
int SafeStrtoi(const uint8_t* data, size_t size) {
    char* endptr;
    char* str = SafeStrndup(data, size, size);
    if (!str) return 0;
    int val = strtol(str, &endptr, 10);
    free(str);
    return val;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for basic operations
    if (size < 10) return 0;

    // Initialize variables
    cmsHANDLE hIT8 = cmsIT8Alloc(nullptr); // Corrected to pass nullptr as ContextID
    cmsHPROFILE hProfile = nullptr;
    cmsCIExyY whitePoint;
    char* patch = nullptr;
    char* sample = nullptr;
    char* val = nullptr;
    double tac = 0.0;
    cmsUInt32Number model = 0;

    // Set up white point from fuzz input
    whitePoint.x = SafeStrtod(data, size);
    whitePoint.y = SafeStrtod(data + sizeof(double), size - sizeof(double));
    whitePoint.Y = 1.0;

    // Create a Lab4 profile
    hProfile = cmsCreateLab4ProfileTHR(nullptr, &whitePoint);
    if (!hProfile) goto cleanup;

    // Set data in IT8 table
    patch = SafeStrndup(data + 2 * sizeof(double), size - 2 * sizeof(double), 255);
    sample = SafeStrndup(data + 3 * sizeof(double), size - 3 * sizeof(double), 255);
    val = SafeStrndup(data + 4 * sizeof(double), size - 4 * sizeof(double), 255);
    if (!patch || !sample || !val) goto cleanup;

    if (!cmsIT8SetData(hIT8, patch, sample, val)) goto cleanup;

    // Check if the profile is a matrix shaper
    if (cmsIsMatrixShaper(hProfile)) {
        // Detect TAC for the profile
        tac = cmsDetectTAC(hProfile);
    }

    // Get the header model
    model = cmsGetHeaderModel(hProfile);

cleanup:
    // Free allocated resources
    if (hIT8) cmsIT8Free(hIT8);
    if (hProfile) cmsCloseProfile(hProfile);
    free(patch);
    free(sample);
    free(val);

    return 0;
}
