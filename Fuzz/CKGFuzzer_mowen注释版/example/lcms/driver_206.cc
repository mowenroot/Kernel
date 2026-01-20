#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <cmath>

// Function to safely convert fuzz input to a double
double safe_double_from_bytes(const uint8_t* data, size_t size, size_t& offset) {
    if (offset + sizeof(double) > size) {
        return 0.0; // Return a default value if not enough data
    }
    double value;
    memcpy(&value, data + offset, sizeof(double));
    offset += sizeof(double);
    return value;
}

// Function to safely convert fuzz input to a float
float safe_float_from_bytes(const uint8_t* data, size_t size, size_t& offset) {
    if (offset + sizeof(float) > size) {
        return 0.0f; // Return a default value if not enough data
    }
    float value;
    memcpy(&value, data + offset, sizeof(float));
    offset += sizeof(float);
    return value;
}

// Function to safely convert fuzz input to an int
int safe_int_from_bytes(const uint8_t* data, size_t size, size_t& offset) {
    if (offset + sizeof(int) > size) {
        return 0; // Return a default value if not enough data
    }
    int value;
    memcpy(&value, data + offset, sizeof(int));
    offset += sizeof(int);
    return value;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize offsets for parsing input data
    size_t offset = 0;

    // Initialize all structures with default values to avoid undefined behavior
    cmsCIEXYZ whitePoint = {1.0, 1.0, 1.0};
    cmsCIEXYZ xyz = {safe_double_from_bytes(data, size, offset), safe_double_from_bytes(data, size, offset), safe_double_from_bytes(data, size, offset)};
    cmsCIExyY xyY = {0.0, 0.0, 0.0};
    cmsCIELab lab = {safe_double_from_bytes(data, size, offset), safe_double_from_bytes(data, size, offset), safe_double_from_bytes(data, size, offset)};
    cmsCIELCh lch = {safe_double_from_bytes(data, size, offset), safe_double_from_bytes(data, size, offset), safe_double_from_bytes(data, size, offset)};

    // Ensure all inputs are within reasonable bounds to prevent excessive memory usage
    if (xyz.X < 0.0 || xyz.X > 1.0 || xyz.Y < 0.0 || xyz.Y > 1.0 || xyz.Z < 0.0 || xyz.Z > 1.0) {
        return 0;
    }

    // Call cmsXYZ2xyY
    cmsXYZ2xyY(&xyY, &xyz);

    // Call cmsXYZ2Lab
    cmsXYZ2Lab(&whitePoint, &lab, &xyz);

    // Call cmsLab2XYZ
    cmsCIEXYZ xyz_converted;
    cmsLab2XYZ(&whitePoint, &xyz_converted, &lab);

    // Call cmsLCh2Lab
    cmsLCh2Lab(&lab, &lch);

    // Call cmsLab2LCh
    cmsLab2LCh(&lch, &lab);

    // Call cmsDesaturateLab
    double amax = safe_double_from_bytes(data, size, offset);
    double amin = safe_double_from_bytes(data, size, offset);
    double bmax = safe_double_from_bytes(data, size, offset);
    double bmin = safe_double_from_bytes(data, size, offset);

    if (amax < amin || bmax < bmin) {
        return 0; // Invalid bounds, exit early
    }

    cmsDesaturateLab(&lab, amax, amin, bmax, bmin);

    // No need to free any resources as all are stack-allocated
    return 0;
}
