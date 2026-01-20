#include "lcms2.h"
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

// Function to safely create a cmsCIExyY structure from fuzz input
cmsCIExyY* create_cmsCIExyY(const uint8_t* data, size_t size) {
    if (size < sizeof(cmsCIExyY)) return nullptr;
    cmsCIExyY* xyY = (cmsCIExyY*)malloc(sizeof(cmsCIExyY));
    if (!xyY) return nullptr;
    memcpy(xyY, data, sizeof(cmsCIExyY));
    return xyY;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for the operations
    if (size < sizeof(cmsCIExyY) + 2 * sizeof(cmsUInt32Number)) return 0;

    // Extract the white point from the fuzz input
    cmsCIExyY* whitePoint = create_cmsCIExyY(data, sizeof(cmsCIExyY));
    if (!whitePoint) return 0;

    // Extract the input and output formats from the fuzz input
    cmsUInt32Number inputFormat = *((cmsUInt32Number*)(data + sizeof(cmsCIExyY)));
    cmsUInt32Number outputFormat = *((cmsUInt32Number*)(data + sizeof(cmsCIExyY) + sizeof(cmsUInt32Number)));

    // Create profiles
    cmsHPROFILE lab4Profile = cmsCreateLab4ProfileTHR(NULL, whitePoint);
    cmsHPROFILE lab2Profile = cmsCreateLab2ProfileTHR(NULL, whitePoint);

    // Check if profiles were created successfully
    if (!lab4Profile || !lab2Profile) {
        free(whitePoint);
        if (lab4Profile) cmsCloseProfile(lab4Profile);
        if (lab2Profile) cmsCloseProfile(lab2Profile);
        return 0;
    }

    // Create a transform
    cmsHTRANSFORM transform = cmsCreateTransform(lab4Profile, inputFormat, lab2Profile, outputFormat, INTENT_PERCEPTUAL, 0);
    if (!transform) {
        free(whitePoint);
        cmsCloseProfile(lab4Profile);
        cmsCloseProfile(lab2Profile);
        return 0;
    }

    // Clean up
    cmsDeleteTransform(transform);
    cmsCloseProfile(lab4Profile);
    cmsCloseProfile(lab2Profile);
    free(whitePoint);

    return 0;
}
