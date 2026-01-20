#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely convert a float from the fuzz input
float safe_float_from_data(const uint8_t* data, size_t size, size_t& offset) {
    if (offset + sizeof(float) > size) {
        return 0.0f; // Return a default value if not enough data
    }
    float value;
    memcpy(&value, data + offset, sizeof(float));
    offset += sizeof(float);
    return value;
}

// Function to safely convert a uint16_t from the fuzz input
uint16_t safe_uint16_from_data(const uint8_t* data, size_t size, size_t& offset) {
    if (offset + sizeof(uint16_t) > size) {
        return 0; // Return a default value if not enough data
    }
    uint16_t value;
    memcpy(&value, data + offset, sizeof(uint16_t));
    offset += sizeof(uint16_t);
    return value;
}

// Function to safely convert a cmsCIELab from the fuzz input
void safe_cmsCIELab_from_data(const uint8_t* data, size_t size, size_t& offset, cmsCIELab& Lab) {
    Lab.L = safe_float_from_data(data, size, offset);
    Lab.a = safe_float_from_data(data, size, offset);
    Lab.b = safe_float_from_data(data, size, offset);
}

// Function to safely convert a cmsCIEXYZ from the fuzz input
void safe_cmsCIEXYZ_from_data(const uint8_t* data, size_t size, size_t& offset, cmsCIEXYZ& XYZ) {
    XYZ.X = safe_float_from_data(data, size, offset);
    XYZ.Y = safe_float_from_data(data, size, offset);
    XYZ.Z = safe_float_from_data(data, size, offset);
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    size_t offset = 0;
    cmsCIELab Lab;
    cmsCIEXYZ XYZ;
    cmsUInt16Number XYZEncoded[3];
    cmsUInt16Number LabEncoded[3];
    cmsFloat32Number toneCurveValue;
    cmsFloat32Number toneCurveResult;
    cmsToneCurve* toneCurve = cmsBuildTabulatedToneCurveFloat(NULL, 256, NULL);

    // Ensure tone curve is valid
    if (!toneCurve) {
        return 0;
    }

    // Extract data from fuzz input
    safe_cmsCIELab_from_data(data, size, offset, Lab);
    safe_cmsCIEXYZ_from_data(data, size, offset, XYZ);
    toneCurveValue = safe_float_from_data(data, size, offset);

    // Call cmsLab2XYZ
    cmsLab2XYZ(NULL, &XYZ, &Lab);

    // Call cmsFloat2XYZEncoded
    cmsFloat2XYZEncoded(XYZEncoded, &XYZ);

    // Call cmsEvalToneCurve16
    cmsUInt16Number toneCurve16Value = safe_uint16_from_data(data, size, offset);
    cmsEvalToneCurve16(toneCurve, toneCurve16Value);

    // Call cmsFloat2LabEncoded
    cmsFloat2LabEncoded(LabEncoded, &Lab);

    // Call cmsFloat2LabEncodedV2
    cmsFloat2LabEncodedV2(LabEncoded, &Lab);

    // Call cmsEvalToneCurveFloat
    toneCurveResult = cmsEvalToneCurveFloat(toneCurve, toneCurveValue);

    // Clean up
    cmsFreeToneCurve(toneCurve);

    return 0;
}
