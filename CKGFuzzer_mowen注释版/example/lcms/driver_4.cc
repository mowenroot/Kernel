#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>
#include <string> // Include string header to fix std::string errors

// Function to safely convert a byte array to a double
double safe_byte_to_double(const uint8_t* data, size_t size) {
    if (size < sizeof(double)) {
        return 0.0; // Return a default value if the size is insufficient
    }
    double value;
    memcpy(&value, data, sizeof(double));
    return value;
}

// Function to safely convert a byte array to an integer
int safe_byte_to_int(const uint8_t* data, size_t size) {
    if (size < sizeof(int)) {
        return 0; // Return a default value if the size is insufficient
    }
    int value;
    memcpy(&value, data, sizeof(int));
    return value;
}

// Function to safely convert a byte array to a string
std::string safe_byte_to_string(const uint8_t* data, size_t size) {
    if (size == 0) {
        return ""; // Return an empty string if the size is zero
    }
    return std::string(reinterpret_cast<const char*>(data), size);
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for our operations
    if (size < sizeof(double) + sizeof(int) + sizeof(int) + sizeof(int)) {
        return 0; // Insufficient data, exit early
    }

    // Extract values from the fuzzer input
    double lambda = safe_byte_to_double(data, sizeof(double));
    int row = safe_byte_to_int(data + sizeof(double), sizeof(int));
    int col = safe_byte_to_int(data + sizeof(double) + sizeof(int), sizeof(int));
    int prop_index = safe_byte_to_int(data + sizeof(double) + 2 * sizeof(int), sizeof(int));

    // Create an IT8 handler
    cmsHANDLE hIT8 = cmsIT8Alloc(NULL);
    if (!hIT8) {
        return 0; // Failed to allocate IT8 handler
    }

    // Set a property using cmsIT8SetPropertyDbl
    std::string prop_name = "Property" + std::to_string(prop_index);
    cmsBool set_prop_result = cmsIT8SetPropertyDbl(hIT8, prop_name.c_str(), lambda);
    if (!set_prop_result) {
        cmsIT8Free(hIT8);
        return 0; // Failed to set property
    }

    // Enumerate properties using cmsIT8EnumProperties
    char** property_names = nullptr;
    cmsUInt32Number num_properties = cmsIT8EnumProperties(hIT8, &property_names);
    if (num_properties == 0 || !property_names) {
        cmsIT8Free(hIT8);
        return 0; // No properties or failed to enumerate
    }

    // Get data from a specific row and column using cmsIT8GetDataRowColDbl
    cmsFloat64Number data_value = cmsIT8GetDataRowColDbl(hIT8, row, col);

    // Create a tone curve
    cmsToneCurve* tone_curve = cmsBuildTabulatedToneCurve16(NULL, 256, nullptr);
    if (!tone_curve) {
        cmsIT8Free(hIT8);
        return 0; // Failed to create tone curve
    }

    // Smooth the tone curve using cmsSmoothToneCurve
    cmsBool smooth_result = cmsSmoothToneCurve(tone_curve, lambda);
    if (!smooth_result) {
        cmsFreeToneCurve(tone_curve);
        cmsIT8Free(hIT8);
        return 0; // Failed to smooth tone curve
    }

    // Check if the tone curve is monotonic using cmsIsToneCurveMonotonic
    cmsBool is_monotonic = cmsIsToneCurveMonotonic(tone_curve);

    // Clean up resources
    cmsFreeToneCurve(tone_curve);
    cmsIT8Free(hIT8);
    if (property_names) {
        cmsIT8Free(hIT8); // Assuming cmsIT8Free can handle array cleanup
    }

    return 0; // Return 0 to indicate successful execution
}
