#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

// Function to safely extract a uint32_t from the fuzz input
uint32_t SafeExtractUInt32(const uint8_t* data, size_t size, size_t& offset) {
    if (offset + sizeof(uint32_t) > size) {
        return 0; // Default value if not enough data
    }
    uint32_t value = *reinterpret_cast<const uint32_t*>(data + offset);
    offset += sizeof(uint32_t);
    return value;
}

// Function to safely extract a double from the fuzz input
double SafeExtractDouble(const uint8_t* data, size_t size, size_t& offset) {
    if (offset + sizeof(double) > size) {
        return 0.0; // Default value if not enough data
    }
    double value = *reinterpret_cast<const double*>(data + offset);
    offset += sizeof(double);
    return value;
}

// Function to safely extract a string from the fuzz input
const char* SafeExtractString(const uint8_t* data, size_t size, size_t& offset, size_t max_len) {
    if (offset + max_len > size) {
        return nullptr; // Default value if not enough data
    }
    const char* str = reinterpret_cast<const char*>(data + offset);
    offset += max_len;
    return str;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    size_t offset = 0;
    cmsContext context = cmsCreateContext(nullptr, nullptr);
    if (!context) return 0;

    // Extract inputs from fuzz data
    uint32_t inputFormat = SafeExtractUInt32(data, size, offset);
    uint32_t outputFormat = SafeExtractUInt32(data, size, offset);
    uint32_t intent = SafeExtractUInt32(data, size, offset);
    uint32_t flags = SafeExtractUInt32(data, size, offset);
    double whitePointX = SafeExtractDouble(data, size, offset);
    double whitePointY = SafeExtractDouble(data, size, offset);
    double whitePointZ = SafeExtractDouble(data, size, offset);
    const char* patch = SafeExtractString(data, size, offset, 64);
    const char* sample = SafeExtractString(data, size, offset, 64); // Added max_len parameter
    double value = SafeExtractDouble(data, size, offset);

    // Create Lab4 profile
    cmsCIExyY whitePoint = {whitePointX, whitePointY, whitePointZ};
    cmsHPROFILE labProfile = cmsCreateLab4ProfileTHR(context, &whitePoint);
    if (!labProfile) {
        cmsDeleteContext(context);
        return 0;
    }

    // Create transform
    cmsHTRANSFORM transform = cmsCreateTransformTHR(context, labProfile, inputFormat, labProfile, outputFormat, intent, flags);
    if (!transform) {
        cmsCloseProfile(labProfile);
        cmsDeleteContext(context);
        return 0;
    }

    // Check if CLUT is supported
    cmsBool isCLUTSupported = cmsIsCLUT(labProfile, intent, LCMS_USED_AS_OUTPUT);

    // Detect destination black point
    cmsCIEXYZ blackPoint;
    cmsBool blackPointDetected = cmsDetectDestinationBlackPoint(&blackPoint, labProfile, intent, flags);

    // Set IT8 data
    cmsHANDLE it8 = cmsIT8Alloc(context);
    if (it8) {
        cmsIT8SetDataDbl(it8, patch, sample, value);
        cmsIT8Free(it8);
    }

    // Clean up
    cmsDeleteTransform(transform);
    cmsCloseProfile(labProfile);
    cmsDeleteContext(context);

    return 0;
}
