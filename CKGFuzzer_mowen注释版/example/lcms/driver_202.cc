#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely extract a uint32_t value from the fuzz input
uint32_t SafeExtractUInt32(const uint8_t* data, size_t size, size_t& offset) {
    if (offset + sizeof(uint32_t) > size) {
        return 0; // Default value if not enough data
    }
    uint32_t value;
    memcpy(&value, data + offset, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    return value;
}

// Function to safely extract a cmsCIExyY value from the fuzz input
cmsCIExyY SafeExtractCIExyY(const uint8_t* data, size_t size, size_t& offset) {
    cmsCIExyY value;
    if (offset + sizeof(cmsCIExyY) > size) {
        memset(&value, 0, sizeof(cmsCIExyY)); // Default value if not enough data
        return value;
    }
    memcpy(&value, data + offset, sizeof(cmsCIExyY));
    offset += sizeof(cmsCIExyY);
    return value;
}

// Function to safely extract a cmsCIExyYTRIPLE value from the fuzz input
cmsCIExyYTRIPLE SafeExtractCIExyYTRIPLE(const uint8_t* data, size_t size, size_t& offset) {
    cmsCIExyYTRIPLE value;
    if (offset + sizeof(cmsCIExyYTRIPLE) > size) {
        memset(&value, 0, sizeof(cmsCIExyYTRIPLE)); // Default value if not enough data
        return value;
    }
    memcpy(&value, data + offset, sizeof(cmsCIExyYTRIPLE));
    offset += sizeof(cmsCIExyYTRIPLE);
    return value;
}

// Function to safely extract a cmsToneCurve* array from the fuzz input
cmsToneCurve** SafeExtractToneCurves(const uint8_t* data, size_t size, size_t& offset) {
    cmsToneCurve** curves = (cmsToneCurve**)malloc(3 * sizeof(cmsToneCurve*));
    if (!curves) {
        return nullptr;
    }
    for (int i = 0; i < 3; ++i) {
        if (offset + sizeof(cmsToneCurve*) > size) {
            curves[i] = nullptr; // Default value if not enough data
        } else {
            memcpy(&curves[i], data + offset, sizeof(cmsToneCurve*));
            offset += sizeof(cmsToneCurve*);
        }
    }
    return curves;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    size_t offset = 0;
    cmsHPROFILE profiles[6] = {nullptr};
    cmsHTRANSFORM transform = nullptr;

    // Extract input values from fuzz data
    uint32_t inputFormat = SafeExtractUInt32(data, size, offset);
    uint32_t outputFormat = SafeExtractUInt32(data, size, offset);
    uint32_t nIntent = SafeExtractUInt32(data, size, offset);
    uint32_t proofingIntent = SafeExtractUInt32(data, size, offset);
    uint32_t dwFlags = SafeExtractUInt32(data, size, offset);
    cmsCIExyY whitePoint = SafeExtractCIExyY(data, size, offset);
    cmsCIExyYTRIPLE primaries = SafeExtractCIExyYTRIPLE(data, size, offset);
    cmsToneCurve** transferFunctions = SafeExtractToneCurves(data, size, offset);

    // Create profiles
    profiles[0] = cmsCreate_sRGBProfile();
    profiles[1] = cmsCreateRGBProfile(&whitePoint, &primaries, transferFunctions);
    profiles[2] = cmsCreateLab4Profile(&whitePoint);
    profiles[3] = cmsCreateLab2Profile(&whitePoint);
    profiles[4] = cmsCreateXYZProfile();
    profiles[5] = cmsCreateProofingTransform(profiles[0], inputFormat, profiles[1], outputFormat, profiles[2], nIntent, proofingIntent, dwFlags);

    // Error handling for profile creation
    for (int i = 0; i < 6; ++i) {
        if (!profiles[i]) {
            // Handle error, possibly log or return early
            goto cleanup;
        }
    }

    // Create a proofing transform
    transform = cmsCreateProofingTransform(profiles[0], inputFormat, profiles[1], outputFormat, profiles[2], nIntent, proofingIntent, dwFlags);
    if (!transform) {
        // Handle error, possibly log or return early
        goto cleanup;
    }

cleanup:
    // Free resources
    if (transform) {
        cmsDeleteTransform(transform);
    }
    for (int i = 0; i < 6; ++i) {
        if (profiles[i]) {
            cmsCloseProfile(profiles[i]);
        }
    }
    if (transferFunctions) {
        free(transferFunctions);
    }

    return 0;
}
