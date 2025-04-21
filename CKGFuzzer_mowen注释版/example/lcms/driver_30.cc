#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely extract a uint32_t from the fuzzer input
uint32_t SafeExtractUInt32(const uint8_t* data, size_t size, size_t& offset) {
    if (offset + sizeof(uint32_t) > size) {
        return 0; // Return a default value if not enough data
    }
    uint32_t value;
    memcpy(&value, data + offset, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    return value;
}

// Function to safely extract a cmsCIExyY from the fuzzer input
cmsCIExyY SafeExtractCIExyY(const uint8_t* data, size_t size, size_t& offset) {
    cmsCIExyY xyY;
    if (offset + sizeof(cmsCIExyY) > size) {
        xyY.x = 0.0;
        xyY.y = 0.0;
        xyY.Y = 0.0;
        return xyY; // Return a default value if not enough data
    }
    memcpy(&xyY, data + offset, sizeof(cmsCIExyY));
    offset += sizeof(cmsCIExyY);
    return xyY;
}

// Function to safely extract a cmsUInt16Number array from the fuzzer input
void SafeExtractUInt16Array(const uint8_t* data, size_t size, size_t& offset, cmsUInt16Number* array, size_t count) {
    if (offset + count * sizeof(cmsUInt16Number) > size) {
        memset(array, 0, count * sizeof(cmsUInt16Number));
        return; // Return a default value if not enough data
    }
    memcpy(array, data + offset, count * sizeof(cmsUInt16Number));
    offset += count * sizeof(cmsUInt16Number);
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    size_t offset = 0;
    cmsHPROFILE hProfile = nullptr;
    cmsCIExyY whitePoint;
    uint32_t flags;
    cmsUInt16Number in[3], out[3];

    // Extract data from fuzzer input
    whitePoint = SafeExtractCIExyY(data, size, offset);
    flags = SafeExtractUInt32(data, size, offset);
    SafeExtractUInt16Array(data, size, offset, in, 3);

    // Create a Lab profile
    hProfile = cmsCreateLab2ProfileTHR(nullptr, &whitePoint);
    if (!hProfile) {
        return 0; // Failed to create profile
    }

    // Check if the profile is a matrix shaper
    cmsBool isMatrixShaper = cmsIsMatrixShaper(hProfile);

    // Set header flags
    cmsSetHeaderFlags(hProfile, flags);

    // Detect TAC
    cmsFloat64Number tac = cmsDetectTAC(hProfile);

    // Read the AToB0 tag and ensure it is a cmsPipeline
    cmsPipeline* lut = (cmsPipeline*)cmsReadTag(hProfile, cmsSigAToB0Tag);
    if (!lut) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Evaluate the pipeline
    cmsPipelineEval16(in, out, lut);

    // Clean up
    if (hProfile) {
        cmsCloseProfile(hProfile);
    }

    return 0;
}
