#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely copy data from the fuzz input to a buffer
void safe_copy(void* dest, const uint8_t* src, size_t size) {
    if (size > 0) {
        memcpy(dest, src, size);
    }
}

// Function to safely convert fuzz input to a 16-bit integer array
void safe_convert_to_16bit_array(cmsUInt16Number* dest, const uint8_t* src, size_t size) {
    for (size_t i = 0; i < size / 2; ++i) {
        dest[i] = (src[i * 2] << 8) | src[i * 2 + 1];
    }
}

// Function to safely convert fuzz input to a cmsCIExyY structure
void safe_convert_to_xyY(cmsCIExyY* dest, const uint8_t* src, size_t size) {
    if (size >= sizeof(cmsCIExyY)) {
        memcpy(dest, src, sizeof(cmsCIExyY));
    }
}

// Function to safely convert fuzz input to a cmsCIEXYZ structure
void safe_convert_to_XYZ(cmsCIEXYZ* dest, const uint8_t* src, size_t size) {
    if (size >= sizeof(cmsCIEXYZ)) {
        memcpy(dest, src, sizeof(cmsCIEXYZ));
    }
}

// Function to safely convert fuzz input to a cmsCIELab structure
void safe_convert_to_Lab(cmsCIELab* dest, const uint8_t* src, size_t size) {
    if (size >= sizeof(cmsCIELab)) {
        memcpy(dest, src, sizeof(cmsCIELab));
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for the operations
    if (size < sizeof(cmsUInt16Number) * 3 + sizeof(cmsCIExyY) + sizeof(cmsCIEXYZ) + sizeof(cmsCIELab)) {
        return 0;
    }

    // Allocate memory for the structures
    cmsCIELab* lab = (cmsCIELab*)malloc(sizeof(cmsCIELab));
    cmsCIEXYZ* xyz = (cmsCIEXYZ*)malloc(sizeof(cmsCIEXYZ));
    cmsCIExyY* xyY = (cmsCIExyY*)malloc(sizeof(cmsCIExyY));
    cmsUInt16Number* encodedLab = (cmsUInt16Number*)malloc(sizeof(cmsUInt16Number) * 3);
    cmsUInt16Number* encodedXYZ = (cmsUInt16Number*)malloc(sizeof(cmsUInt16Number) * 3);

    // Initialize the structures with fuzz input data
    safe_convert_to_16bit_array(encodedLab, data, sizeof(cmsUInt16Number) * 3);
    safe_convert_to_xyY(xyY, data + sizeof(cmsUInt16Number) * 3, sizeof(cmsCIExyY));
    safe_convert_to_XYZ(xyz, data + sizeof(cmsUInt16Number) * 3 + sizeof(cmsCIExyY), sizeof(cmsCIEXYZ));
    safe_convert_to_Lab(lab, data + sizeof(cmsUInt16Number) * 3 + sizeof(cmsCIExyY) + sizeof(cmsCIEXYZ), sizeof(cmsCIELab));

    // Call the APIs
    cmsLabEncoded2FloatV2(lab, encodedLab);
    cmsxyY2XYZ(xyz, xyY);
    cmsXYZ2Lab(cmsD50_XYZ(), lab, xyz);
    cmsXYZEncoded2Float(xyz, encodedXYZ);
    cmsLab2XYZ(cmsD50_XYZ(), xyz, lab);
    cmsLabEncoded2Float(lab, encodedLab);

    // Free allocated memory
    free(lab);
    free(xyz);
    free(xyY);
    free(encodedLab);
    free(encodedXYZ);

    return 0;
}
