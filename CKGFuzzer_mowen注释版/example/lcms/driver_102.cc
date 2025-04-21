#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely convert a uint8_t array to a cmsCIExyY structure
bool ConvertToCIExyY(const uint8_t* data, size_t size, cmsCIExyY* out) {
    if (size < sizeof(cmsCIExyY)) return false;
    memcpy(out, data, sizeof(cmsCIExyY));
    return true;
}

// Function to safely convert a uint8_t array to a cmsUInt16Number array
bool ConvertToUInt16Array(const uint8_t* data, size_t size, cmsUInt16Number* out, size_t count) {
    if (size < count * sizeof(cmsUInt16Number)) return false;
    memcpy(out, data, count * sizeof(cmsUInt16Number));
    return true;
}

// The main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    cmsContext context = cmsCreateContext(NULL, NULL);
    cmsHPROFILE profile = NULL;
    cmsHANDLE gbd = NULL;
    cmsStage* stage = NULL;
    cmsPipeline* pipeline = NULL;
    cmsUInt16Number in[3] = {0};
    cmsUInt16Number out[3] = {0};
    cmsCIExyY whitePoint = {0.0, 0.0, 0.0};

    // Ensure context creation was successful
    if (!context) return 0;

    // Convert fuzzer input to cmsCIExyY structure
    if (!ConvertToCIExyY(data, size, &whitePoint)) {
        cmsDeleteContext(context);
        return 0;
    }

    // Create a Lab profile
    profile = cmsCreateLab2ProfileTHR(context, &whitePoint);
    if (!profile) {
        cmsDeleteContext(context);
        return 0;
    }

    // Allocate memory for a cmsGDB structure
    gbd = cmsGBDAlloc(context);
    if (!gbd) {
        cmsCloseProfile(profile);
        cmsDeleteContext(context);
        return 0;
    }

    // Convert fuzzer input to cmsUInt16Number array
    if (!ConvertToUInt16Array(data, size, in, 3)) {
        cmsGBDFree(gbd);
        cmsCloseProfile(profile);
        cmsDeleteContext(context);
        return 0;
    }

    // Evaluate the pipeline
    pipeline = static_cast<cmsPipeline*>(cmsReadTag(profile, cmsSigAToB0Tag)); // Cast the result to cmsPipeline*
    if (pipeline) {
        cmsPipelineEval16(in, out, pipeline);
    }

    // Free resources
    if (pipeline) cmsPipelineFree(pipeline);
    cmsGBDFree(gbd);
    cmsCloseProfile(profile);
    cmsDeleteContext(context);

    return 0;
}
