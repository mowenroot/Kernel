#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely extract a double from the fuzz input
bool extractDouble(const uint8_t* data, size_t size, size_t& offset, double& value) {
    if (offset + sizeof(double) > size) {
        return false;
    }
    value = *reinterpret_cast<const double*>(data + offset);
    offset += sizeof(double);
    return true;
}

// Function to safely extract a float from the fuzz input
bool extractFloat(const uint8_t* data, size_t size, size_t& offset, float& value) {
    if (offset + sizeof(float) > size) {
        return false;
    }
    value = *reinterpret_cast<const float*>(data + offset);
    offset += sizeof(float);
    return true;
}

// Function to safely extract an int from the fuzz input
bool extractInt(const uint8_t* data, size_t size, size_t& offset, int& value) {
    if (offset + sizeof(int) > size) {
        return false;
    }
    value = *reinterpret_cast<const int*>(data + offset);
    offset += sizeof(int);
    return true;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    cmsCIEXYZ whitePoint;
    cmsCIEXYZ xyz;
    cmsCIExyY xyY;
    cmsCIELab lab;
    cmsCIELCh lch;

    size_t offset = 0;

    // Extract values from fuzz input
    if (!extractDouble(data, size, offset, whitePoint.X) ||
        !extractDouble(data, size, offset, whitePoint.Y) ||
        !extractDouble(data, size, offset, whitePoint.Z) ||
        !extractDouble(data, size, offset, xyz.X) ||
        !extractDouble(data, size, offset, xyz.Y) ||
        !extractDouble(data, size, offset, xyz.Z)) {
        return 0;
    }

    // Call cmsXYZ2xyY
    cmsXYZ2xyY(&xyY, &xyz);

    // Call cmsXYZ2Lab
    cmsXYZ2Lab(&whitePoint, &lab, &xyz);

    // Call cmsxyY2XYZ
    cmsxyY2XYZ(&xyz, &xyY);

    // Call cmsLab2XYZ
    cmsLab2XYZ(&whitePoint, &xyz, &lab);

    // Call cmsLab2LCh
    cmsLab2LCh(&lch, &lab);

    // Call cmsLCh2Lab
    cmsLCh2Lab(&lab, &lch);

    return 0;
}
