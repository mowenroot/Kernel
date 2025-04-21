#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

// Function to safely extract a uint8_t value from the fuzz input
uint8_t safe_extract_uint8(const uint8_t* data, size_t size, size_t& offset) {
    if (offset >= size) {
        return 0; // Default value if out of bounds
    }
    return data[offset++];
}

// Function to safely extract a size_t value from the fuzz input
size_t safe_extract_size_t(const uint8_t* data, size_t size, size_t& offset) {
    if (offset + sizeof(size_t) > size) {
        return 0; // Default value if out of bounds
    }
    size_t value;
    memcpy(&value, data + offset, sizeof(size_t));
    offset += sizeof(size_t);
    return value;
}

// Function to safely extract a cmsCIExyY value from the fuzz input
cmsCIExyY safe_extract_cmsCIExyY(const uint8_t* data, size_t size, size_t& offset) {
    cmsCIExyY value;
    if (offset + sizeof(cmsCIExyY) > size) {
        value.x = 0.0;
        value.y = 0.0;
        value.Y = 0.0;
    } else {
        memcpy(&value, data + offset, sizeof(cmsCIExyY));
        offset += sizeof(cmsCIExyY);
    }
    return value;
}

// Function to safely extract a cmsCIExyYTRIPLE value from the fuzz input
cmsCIExyYTRIPLE safe_extract_cmsCIExyYTRIPLE(const uint8_t* data, size_t size, size_t& offset) {
    cmsCIExyYTRIPLE value;
    if (offset + sizeof(cmsCIExyYTRIPLE) > size) {
        value.Red.x = 0.0;
        value.Red.y = 0.0;
        value.Red.Y = 0.0;
        value.Green.x = 0.0;
        value.Green.y = 0.0;
        value.Green.Y = 0.0;
        value.Blue.x = 0.0;
        value.Blue.y = 0.0;
        value.Blue.Y = 0.0;
    } else {
        memcpy(&value, data + offset, sizeof(cmsCIExyYTRIPLE));
        offset += sizeof(cmsCIExyYTRIPLE);
    }
    return value;
}

// Function to safely extract a cmsToneCurve* array from the fuzz input
cmsToneCurve** safe_extract_cmsToneCurve_array(const uint8_t* data, size_t size, size_t& offset, size_t count) {
    cmsToneCurve** curves = (cmsToneCurve**)malloc(count * sizeof(cmsToneCurve*));
    if (!curves) {
        return nullptr;
    }
    for (size_t i = 0; i < count; ++i) {
        curves[i] = nullptr; // Initialize to nullptr
    }
    return curves;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize context
    cmsContext context = cmsCreateContext(nullptr, nullptr);
    if (!context) {
        return 0;
    }

    // Initialize variables
    size_t offset = 0;
    cmsHPROFILE profiles[6] = {nullptr};

    // Extract input parameters
    cmsCIExyY whitePoint = safe_extract_cmsCIExyY(data, size, offset);
    cmsCIExyYTRIPLE primaries = safe_extract_cmsCIExyYTRIPLE(data, size, offset);
    cmsToneCurve** transferFunctions = safe_extract_cmsToneCurve_array(data, size, offset, 3);
    if (!transferFunctions) {
        cmsDeleteContext(context);
        return 0;
    }

    // Create profiles
    profiles[0] = cmsCreateLab4ProfileTHR(context, &whitePoint);
    profiles[1] = cmsCreateNULLProfileTHR(context);
    profiles[2] = cmsCreateRGBProfileTHR(context, &whitePoint, &primaries, transferFunctions);
    profiles[3] = cmsCreateLab2ProfileTHR(context, &whitePoint);
    profiles[4] = cmsCreateXYZProfileTHR(context);
    profiles[5] = cmsCreate_sRGBProfileTHR(context);

    // Clean up
    for (size_t i = 0; i < 6; ++i) {
        if (profiles[i]) {
            cmsCloseProfile(profiles[i]);
        }
    }
    for (size_t i = 0; i < 3; ++i) {
        if (transferFunctions[i]) {
            cmsFreeToneCurve(transferFunctions[i]);
        }
    }
    free(transferFunctions);
    cmsDeleteContext(context);

    return 0;
}
