#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely extract an integer from the fuzz input
int32_t safe_extract_int(const uint8_t* data, size_t size, size_t& offset, size_t max_size) {
    if (offset + sizeof(int32_t) > size) {
        return 0; // Return a default value if not enough data
    }
    int32_t value = *reinterpret_cast<const int32_t*>(data + offset);
    offset += sizeof(int32_t);
    return value;
}

// Function to safely extract a float from the fuzz input
float safe_extract_float(const uint8_t* data, size_t size, size_t& offset, size_t max_size) {
    if (offset + sizeof(float) > size) {
        return 0.0f; // Return a default value if not enough data
    }
    float value = *reinterpret_cast<const float*>(data + offset);
    offset += sizeof(float);
    return value;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < sizeof(int32_t) * 10 + sizeof(float) * 3) {
        return 0;
    }

    // Initialize variables
    size_t offset = 0;
    cmsCIELCh LCh;
    cmsCIELab Lab;
    cmsCIEXYZ XYZ;
    cmsJCh JCh;
    cmsViewingConditions VC;
    cmsHANDLE hModel = nullptr;

    // Extract data from fuzz input
    LCh.L = safe_extract_float(data, size, offset, size);
    LCh.C = safe_extract_float(data, size, offset, size);
    LCh.h = safe_extract_float(data, size, offset, size);

    VC.whitePoint.X = safe_extract_float(data, size, offset, size);
    VC.whitePoint.Y = safe_extract_float(data, size, offset, size);
    VC.whitePoint.Z = safe_extract_float(data, size, offset, size);
    VC.La = safe_extract_float(data, size, offset, size);
    VC.Yb = safe_extract_float(data, size, offset, size);
    VC.D_value = safe_extract_float(data, size, offset, size);
    VC.surround = static_cast<cmsUInt32Number>(safe_extract_int(data, size, offset, size) % 4); // Ensure valid surround value

    // Initialize CIECAM02 model
    hModel = cmsCIECAM02Init(nullptr, &VC);
    if (!hModel) {
        return 0; // Failed to initialize model
    }

    // Perform color space conversions
    cmsLCh2Lab(&Lab, &LCh);
    cmsLab2LCh(&LCh, &Lab);

    XYZ.X = safe_extract_float(data, size, offset, size);
    XYZ.Y = safe_extract_float(data, size, offset, size);
    XYZ.Z = safe_extract_float(data, size, offset, size);

    cmsCIECAM02Forward(hModel, &XYZ, &JCh);
    cmsCIECAM02Reverse(hModel, &JCh, &XYZ);

    // Clean up
    cmsCIECAM02Done(hModel);

    return 0;
}
