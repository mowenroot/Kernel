#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely extract a float from the fuzz input
float safe_extract_float(const uint8_t* data, size_t& offset, size_t size) {
    if (offset + sizeof(float) > size) {
        return 0.0f; // Return a default value if not enough data
    }
    float value;
    memcpy(&value, data + offset, sizeof(float));
    offset += sizeof(float);
    return value;
}

// Function to safely extract an int from the fuzz input
int safe_extract_int(const uint8_t* data, size_t& offset, size_t size) {
    if (offset + sizeof(int) > size) {
        return 0; // Return a default value if not enough data
    }
    int value;
    memcpy(&value, data + offset, sizeof(int));
    offset += sizeof(int);
    return value;
}

// Function to safely extract a double from the fuzz input
double safe_extract_double(const uint8_t* data, size_t& offset, size_t size) {
    if (offset + sizeof(double) > size) {
        return 0.0; // Return a default value if not enough data
    }
    double value;
    memcpy(&value, data + offset, sizeof(double));
    offset += sizeof(double);
    return value;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Initialize variables
    size_t offset = 0;
    cmsCIELab lab;
    cmsCIELCh lch;
    cmsCIEXYZ xyz;
    cmsJCh jch;
    cmsViewingConditions vc;
    cmsHANDLE hModel = nullptr;

    // Extract values from fuzz input
    lab.L = safe_extract_float(data, offset, size);
    lab.a = safe_extract_float(data, offset, size);
    lab.b = safe_extract_float(data, offset, size);

    vc.whitePoint.X = safe_extract_double(data, offset, size);
    vc.whitePoint.Y = safe_extract_double(data, offset, size);
    vc.whitePoint.Z = safe_extract_double(data, offset, size);
    vc.La = safe_extract_double(data, offset, size);
    vc.Yb = safe_extract_double(data, offset, size);
    vc.D_value = safe_extract_double(data, offset, size);
    vc.surround = static_cast<cmsUInt32Number>(safe_extract_int(data, offset, size)); // Fix: Use cmsUInt32Number instead of cmsSurround

    // Initialize CIECAM02 model
    hModel = cmsCIECAM02Init(nullptr, &vc);
    if (!hModel) {
        return 0; // Failed to initialize model
    }

    // Convert Lab to LCh
    cmsLab2LCh(&lch, &lab);

    // Convert LCh to Lab
    cmsLCh2Lab(&lab, &lch);

    // Convert XYZ to JCh
    xyz.X = safe_extract_double(data, offset, size);
    xyz.Y = safe_extract_double(data, offset, size);
    xyz.Z = safe_extract_double(data, offset, size);
    cmsCIECAM02Forward(hModel, &xyz, &jch);

    // Convert JCh to XYZ
    cmsCIECAM02Reverse(hModel, &jch, &xyz);

    // Clean up resources
    cmsCIECAM02Done(hModel);

    return 0;
}
