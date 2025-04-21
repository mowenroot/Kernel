#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

// Function to safely extract a float from the fuzz input
float SafeExtractFloat(const uint8_t* data, size_t& offset, size_t size) {
    if (offset + sizeof(float) > size) {
        return 0.0f; // Return a default value if not enough data
    }
    float value;
    memcpy(&value, data + offset, sizeof(float));
    offset += sizeof(float);
    return value;
}

// Function to safely extract a double from the fuzz input
double SafeExtractDouble(const uint8_t* data, size_t& offset, size_t size) {
    if (offset + sizeof(double) > size) {
        return 0.0; // Return a default value if not enough data
    }
    double value;
    memcpy(&value, data + offset, sizeof(double));
    offset += sizeof(double);
    return value;
}

// Function to safely extract a 16-bit integer from the fuzz input
cmsUInt16Number SafeExtractUInt16(const uint8_t* data, size_t& offset, size_t size) {
    if (offset + sizeof(cmsUInt16Number) > size) {
        return 0; // Return a default value if not enough data
    }
    cmsUInt16Number value;
    memcpy(&value, data + offset, sizeof(cmsUInt16Number));
    offset += sizeof(cmsUInt16Number);
    return value;
}

// Function to safely extract a cmsCIEXYZ structure from the fuzz input
void SafeExtractCIEXYZ(const uint8_t* data, size_t& offset, size_t size, cmsCIEXYZ& xyz) {
    xyz.X = SafeExtractDouble(data, offset, size);
    xyz.Y = SafeExtractDouble(data, offset, size);
    xyz.Z = SafeExtractDouble(data, offset, size);
}

// Function to safely extract a cmsCIELab structure from the fuzz input
void SafeExtractCIELab(const uint8_t* data, size_t& offset, size_t size, cmsCIELab& lab) {
    lab.L = SafeExtractDouble(data, offset, size);
    lab.a = SafeExtractDouble(data, offset, size);
    lab.b = SafeExtractDouble(data, offset, size);
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    size_t offset = 0;
    cmsUInt16Number XYZ[3] = {0};
    cmsUInt16Number Lab[3] = {0};
    cmsCIEXYZ fXYZ;
    cmsCIELab fLab;
    cmsFloat32Number v;
    cmsFloat64Number gamma;
    cmsFloat64Number precision = 0.01;

    // Extract data from fuzz input
    v = SafeExtractFloat(data, offset, size);
    SafeExtractCIEXYZ(data, offset, size, fXYZ);
    SafeExtractCIELab(data, offset, size, fLab);

    // Create a tone curve for testing
    std::unique_ptr<cmsToneCurve, void(*)(cmsToneCurve*)> toneCurve(cmsBuildGamma(NULL, 2.2), cmsFreeToneCurve);
    if (!toneCurve) {
        return 0; // Failed to create tone curve
    }

    // Test cmsEvalToneCurveFloat
    cmsFloat32Number resultFloat = cmsEvalToneCurveFloat(toneCurve.get(), v);

    // Test cmsFloat2XYZEncoded
    cmsFloat2XYZEncoded(XYZ, &fXYZ);

    // Test cmsEvalToneCurve16
    cmsUInt16Number result16 = cmsEvalToneCurve16(toneCurve.get(), XYZ[0]);

    // Test cmsEstimateGamma
    gamma = cmsEstimateGamma(toneCurve.get(), precision);
    if (gamma < 0.0) {
        // Handle the case where gamma estimation failed
    }

    // Test cmsFloat2LabEncoded
    cmsFloat2LabEncoded(Lab, &fLab);

    // Test cmsFloat2LabEncodedV2
    cmsFloat2LabEncodedV2(Lab, &fLab);

    // Ensure all resources are freed and no memory leaks occur
    return 0;
}
