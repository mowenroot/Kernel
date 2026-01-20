#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely convert fuzzer input to a cmsTagSignature
cmsTagSignature SafeConvertToTagSignature(const uint8_t* data, size_t size) {
    if (size < sizeof(cmsTagSignature)) {
        return (cmsTagSignature)0;
    }
    return *(cmsTagSignature*)data;
}

// Function to safely convert fuzzer input to a cmsUInt32Number
cmsUInt32Number SafeConvertToUInt32(const uint8_t* data, size_t size) {
    if (size < sizeof(cmsUInt32Number)) {
        return 0;
    }
    return *(cmsUInt32Number*)data;
}

// Function to safely convert fuzzer input to a cmsFloat64Number
cmsFloat64Number SafeConvertToFloat64(const uint8_t* data, size_t size) {
    if (size < sizeof(cmsFloat64Number)) {
        return 0.0;
    }
    return *(cmsFloat64Number*)data;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for basic operations
    if (size < sizeof(cmsTagSignature) + sizeof(cmsUInt32Number) + sizeof(cmsFloat64Number)) {
        return 0;
    }

    // Create a profile handle
    cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(NULL);
    if (!hProfile) {
        return 0;
    }

    // Extract inputs for API calls
    cmsTagSignature tagSig = SafeConvertToTagSignature(data, size);
    cmsUInt32Number intent = SafeConvertToUInt32(data + sizeof(cmsTagSignature), size - sizeof(cmsTagSignature));
    cmsFloat64Number version = SafeConvertToFloat64(data + sizeof(cmsTagSignature) + sizeof(cmsUInt32Number), size - sizeof(cmsTagSignature) - sizeof(cmsUInt32Number));

    // Call cmsGetProfileVersion
    cmsFloat64Number profileVersion = cmsGetProfileVersion(hProfile);
    if (profileVersion < 0.0) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Call cmsReadTag
    void* tagData = cmsReadTag(hProfile, tagSig);
    if (tagData) {
        // Handle the tag data if needed
    }

    // Call cmsWriteTag
    cmsBool writeResult = cmsWriteTag(hProfile, tagSig, tagData);
    if (!writeResult) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Call cmsDetectTAC
    cmsFloat64Number tac = cmsDetectTAC(hProfile);
    if (tac < 0.0) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Call cmsDetectBlackPoint
    cmsCIEXYZ blackPoint;
    cmsBool blackPointResult = cmsDetectBlackPoint(&blackPoint, hProfile, intent, 0);
    if (!blackPointResult) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Call cmsDetectDestinationBlackPoint
    cmsCIEXYZ destBlackPoint;
    cmsBool destBlackPointResult = cmsDetectDestinationBlackPoint(&destBlackPoint, hProfile, intent, 0);
    if (!destBlackPointResult) {
        cmsCloseProfile(hProfile);
        return 0;
    }

    // Clean up
    cmsCloseProfile(hProfile);
    return 0;
}
