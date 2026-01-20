#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy a string from fuzz input
char* safe_strndup(const uint8_t* data, size_t size, size_t max_len) {
    size_t len = strnlen((const char*)data, size);
    if (len > max_len) len = max_len;
    char* str = (char*)malloc(len + 1);
    if (str) {
        memcpy(str, data, len);
        str[len] = '\0';
    }
    return str;
}

// Function to safely allocate and copy a buffer from fuzz input
void* safe_memdup(const uint8_t* data, size_t size, size_t max_len) {
    if (size > max_len) size = max_len;
    void* buf = malloc(size);
    if (buf) {
        memcpy(buf, data, size);
    }
    return buf;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < sizeof(cmsCIExyY) + sizeof(cmsCIExyYTRIPLE) + 3 * sizeof(cmsToneCurve*)) {
        return 0;
    }

    // Initialize variables
    cmsHPROFILE profiles[6] = {NULL};
    cmsHTRANSFORM transform = NULL;

    // Extract data for API inputs
    const cmsCIExyY* whitePoint = (const cmsCIExyY*)data;
    const cmsCIExyYTRIPLE* primaries = (const cmsCIExyYTRIPLE*)(data + sizeof(cmsCIExyY));
    cmsToneCurve* transferFunctions[3] = {NULL};
    for (int i = 0; i < 3; ++i) {
        transferFunctions[i] = (cmsToneCurve*)(data + sizeof(cmsCIExyY) + sizeof(cmsCIExyYTRIPLE) + i * sizeof(cmsToneCurve*));
    }

    // Create profiles
    profiles[0] = cmsCreate_sRGBProfile();
    profiles[1] = cmsCreateRGBProfile(whitePoint, primaries, transferFunctions);
    profiles[2] = cmsCreateLab2Profile(whitePoint);
    profiles[3] = cmsCreateXYZProfile();
    profiles[4] = cmsCreateProfilePlaceholder(NULL);

    // Create a proofing transform
    if (profiles[0] && profiles[1] && profiles[2]) {
        transform = cmsCreateProofingTransform(profiles[0], 0, profiles[1], 0, profiles[2], 0, 0, 0);
    }

    // Clean up resources
    if (transform) cmsDeleteTransform(transform);
    for (int i = 0; i < 6; ++i) {
        if (profiles[i]) cmsCloseProfile(profiles[i]);
    }

    return 0;
}
