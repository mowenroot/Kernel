#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Custom error handler function
void CustomErrorHandler(cmsContext ContextID, cmsUInt32Number ErrorCode, const char *Text) {
    // Log or handle the error as needed
    // For simplicity, we just print the error message here
    fprintf(stderr, "Error %u: %s\n", ErrorCode, Text);
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input data is large enough to be useful
    if (size < 4) {
        return 0;
    }

    // Set the custom error handler
    cmsSetLogErrorHandler(CustomErrorHandler);

    // Initialize variables
    cmsHPROFILE hProfile = nullptr;
    cmsBool isCLUT = FALSE;
    cmsFloat64Number tac = 0.0;

    // Create a Lab 4 profile using the fuzz input
    const cmsCIExyY whitePoint = {
        static_cast<cmsFloat64Number>(data[0]) / 255.0,
        static_cast<cmsFloat64Number>(data[1]) / 255.0,
        static_cast<cmsFloat64Number>(data[2]) / 255.0
    };
    hProfile = cmsCreateLab4ProfileTHR(nullptr, &whitePoint);
    if (!hProfile) {
        return 0; // Failed to create profile
    }

    // Check if the profile supports a specific rendering intent
    cmsUInt32Number intent = data[3] % 16; // Intent values are typically 0-15
    cmsUInt32Number direction = data[4] % 3; // Directions are 0-2 (LCMS_USED_AS_INPUT, LCMS_USED_AS_OUTPUT, LCMS_USED_AS_PROOF)
    isCLUT = cmsIsCLUT(hProfile, intent, direction);

    // Detect TAC for the profile
    tac = cmsDetectTAC(hProfile);

    // Clean up resources
    if (hProfile) {
        cmsCloseProfile(hProfile);
    }

    return 0; // Return 0 to indicate success
}
