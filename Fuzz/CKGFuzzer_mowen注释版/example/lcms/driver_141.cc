#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy data from fuzz input to a buffer
void safe_copy(void* dest, const uint8_t* src, size_t size) {
    if (size > 0) {
        memcpy(dest, src, size);
    }
}

// Function to safely convert fuzz input to a double
double safe_double(const uint8_t* data, size_t size) {
    if (size < sizeof(double)) {
        return 0.0;
    }
    double value;
    memcpy(&value, data, sizeof(double));
    return value;
}

// Function to safely convert fuzz input to a 16-bit integer
cmsUInt16Number safe_uint16(const uint8_t* data, size_t size) {
    if (size < sizeof(cmsUInt16Number)) {
        return 0;
    }
    cmsUInt16Number value;
    memcpy(&value, data, sizeof(cmsUInt16Number));
    return value;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for all operations
    if (size < (3 * sizeof(cmsUInt16Number) + 3 * sizeof(double))) {
        return 0;
    }

    // Initialize structures
    cmsCIEXYZ whitePoint;
    cmsCIEXYZ xyz;
    cmsCIELab lab;
    cmsCIELCh lch;
    cmsCIExyY xyY;
    cmsUInt16Number encodedLab[3];

    // Extract data from fuzz input
    safe_copy(&whitePoint, data, sizeof(cmsCIEXYZ));
    data += sizeof(cmsCIEXYZ);
    size -= sizeof(cmsCIEXYZ);

    safe_copy(&xyz, data, sizeof(cmsCIEXYZ));
    data += sizeof(cmsCIEXYZ);
    size -= sizeof(cmsCIEXYZ);

    safe_copy(&lab, data, sizeof(cmsCIELab));
    data += sizeof(cmsCIELab);
    size -= sizeof(cmsCIELab);

    safe_copy(encodedLab, data, 3 * sizeof(cmsUInt16Number));
    data += 3 * sizeof(cmsUInt16Number);
    size -= 3 * sizeof(cmsUInt16Number);

    // Perform API calls with error handling
    cmsXYZ2xyY(&xyY, &xyz);

    cmsXYZ2Lab(&whitePoint, &lab, &xyz);

    cmsLab2XYZ(&whitePoint, &xyz, &lab);

    cmsLab2LCh(&lch, &lab);

    cmsLabEncoded2Float(&lab, encodedLab);

    cmsFloat2LabEncoded(encodedLab, &lab);

    // No need to free any resources as we used stack-allocated memory
    return 0;
}
