#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely extract a uint32_t from the fuzzer input
uint32_t ExtractUint32(const uint8_t* data, size_t size, size_t& offset) {
    if (offset + sizeof(uint32_t) > size) {
        return 0; // Return a default value if not enough data
    }
    uint32_t value = *reinterpret_cast<const uint32_t*>(data + offset);
    offset += sizeof(uint32_t);
    return value;
}

// Function to safely extract a cmsCIExyY from the fuzzer input
cmsCIExyY ExtractCIExyY(const uint8_t* data, size_t size, size_t& offset) {
    cmsCIExyY xyY;
    if (offset + sizeof(cmsCIExyY) > size) {
        memset(&xyY, 0, sizeof(cmsCIExyY)); // Initialize to zero if not enough data
        return xyY;
    }
    memcpy(&xyY, data + offset, sizeof(cmsCIExyY));
    offset += sizeof(cmsCIExyY);
    return xyY;
}

// Function to safely extract a cmsUInt16Number array from the fuzzer input
void ExtractUInt16Array(const uint8_t* data, size_t size, size_t& offset, cmsUInt16Number* array, size_t count) {
    if (offset + count * sizeof(cmsUInt16Number) > size) {
        memset(array, 0, count * sizeof(cmsUInt16Number)); // Initialize to zero if not enough data
        return;
    }
    memcpy(array, data + offset, count * sizeof(cmsUInt16Number));
    offset += count * sizeof(cmsUInt16Number);
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    cmsContext context = cmsCreateContext(NULL, NULL);
    cmsHPROFILE profile = NULL;
    cmsCIExyY whitePoint;
    uint32_t flags;
    cmsUInt16Number in[3], out[3];
    size_t offset = 0;

    // Extract data from fuzzer input
    whitePoint = ExtractCIExyY(data, size, offset);
    flags = ExtractUint32(data, size, offset);
    ExtractUInt16Array(data, size, offset, in, 3);

    // Create a Lab 4 profile
    profile = cmsCreateLab4ProfileTHR(context, &whitePoint);
    if (!profile) {
        cmsDeleteContext(context);
        return 0;
    }

    // Check if the profile is a matrix shaper
    if (cmsIsMatrixShaper(profile)) {
        // Set header flags
        cmsSetHeaderFlags(profile, flags);
    }

    // Detect TAC
    cmsDetectTAC(profile);

    // Evaluate the pipeline
    cmsPipelineEval16(in, out, cmsPipelineAlloc(context, 3, 3));

    // Clean up
    cmsCloseProfile(profile);
    cmsDeleteContext(context);

    return 0;
}
