#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely convert a uint8_t array to a cmsUInt16Number array
void safe_convert_to_cmsUInt16Number(const uint8_t* data, size_t size, cmsUInt16Number* output, size_t output_size) {
    if (size < output_size * sizeof(cmsUInt16Number)) {
        memset(output, 0, output_size * sizeof(cmsUInt16Number));
        return;
    }
    for (size_t i = 0; i < output_size; ++i) {
        output[i] = (data[i * 2] << 8) | data[i * 2 + 1];
    }
}

// Function to safely convert a uint8_t array to a cmsFloat64Number
cmsFloat64Number safe_convert_to_cmsFloat64Number(const uint8_t* data, size_t size, size_t offset) {
    if (offset + sizeof(cmsFloat64Number) > size) {
        return 0.0;
    }
    cmsFloat64Number result;
    memcpy(&result, data + offset, sizeof(cmsFloat64Number));
    return result;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < 3 * sizeof(cmsUInt16Number) + 3 * sizeof(cmsFloat64Number)) {
        return 0;
    }

    // Initialize variables
    cmsCIELab Lab;
    cmsCIELCh LCh;
    cmsCIEXYZ XYZ;
    cmsCIExyY xyY;
    cmsUInt16Number wLab[3];

    // Convert fuzzer input to cmsUInt16Number array
    safe_convert_to_cmsUInt16Number(data, size, wLab, 3);

    // Call cmsLabEncoded2FloatV2
    cmsLabEncoded2FloatV2(&Lab, wLab);

    // Call cmsLab2LCh
    cmsLab2LCh(&LCh, &Lab);

    // Call cmsLCh2Lab
    cmsLCh2Lab(&Lab, &LCh);

    // Convert fuzzer input to cmsFloat64Number for XYZ values
    XYZ.X = safe_convert_to_cmsFloat64Number(data, size, 3 * sizeof(cmsUInt16Number));
    XYZ.Y = safe_convert_to_cmsFloat64Number(data, size, 3 * sizeof(cmsUInt16Number) + sizeof(cmsFloat64Number));
    XYZ.Z = safe_convert_to_cmsFloat64Number(data, size, 3 * sizeof(cmsUInt16Number) + 2 * sizeof(cmsFloat64Number));

    // Call cmsXYZ2xyY
    cmsXYZ2xyY(&xyY, &XYZ);

    // Call cmsxyY2XYZ
    cmsxyY2XYZ(&XYZ, &xyY);

    // Call cmsXYZ2Lab with default white point
    cmsXYZ2Lab(nullptr, &Lab, &XYZ);

    // All resources are automatically managed by the stack, no need for explicit deallocation
    return 0;
}
