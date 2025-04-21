#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely convert fuzzer input to a cmsTagSignature
cmsTagSignature SafeConvertToTagSignature(const uint8_t* data, size_t size) {
    if (size < sizeof(cmsTagSignature)) {
        return (cmsTagSignature)0; // Return a null tag signature if input is too small
    }
    return *reinterpret_cast<const cmsTagSignature*>(data);
}

// Function to safely convert fuzzer input to a cmsUInt32Number
cmsUInt32Number SafeConvertToUInt32(const uint8_t* data, size_t size) {
    if (size < sizeof(cmsUInt32Number)) {
        return 0; // Return 0 if input is too small
    }
    return *reinterpret_cast<const cmsUInt32Number*>(data);
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for basic operations
    if (size < sizeof(cmsTagSignature) + sizeof(cmsUInt32Number)) {
        return 0; // Insufficient data to proceed
    }

    // Create a dummy profile handle for testing purposes
    cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(NULL);
    if (!hProfile) {
        return 0; // Failed to create a profile placeholder
    }

    // Extract tag signature and index from fuzzer input
    cmsTagSignature tagSig = SafeConvertToTagSignature(data, size);
    cmsUInt32Number tagIndex = SafeConvertToUInt32(data + sizeof(cmsTagSignature), size - sizeof(cmsTagSignature));

    // Call cmsGetTagCount to get the number of tags in the profile
    cmsInt32Number tagCount = cmsGetTagCount(hProfile);
    if (tagCount < 0) {
        cmsCloseProfile(hProfile);
        return 0; // Error in getting tag count
    }

    // Call cmsGetTagSignature to get the tag signature at the specified index
    cmsTagSignature retrievedTagSig = cmsGetTagSignature(hProfile, tagIndex % tagCount);
    if (retrievedTagSig == 0) {
        cmsCloseProfile(hProfile);
        return 0; // Invalid tag index
    }

    // Call cmsIsTag to check if the tag exists in the profile
    cmsBool isTagPresent = cmsIsTag(hProfile, tagSig);

    // Call cmsReadTag to read the tag data
    void* tagData = cmsReadTag(hProfile, tagSig);
    if (tagData) {
        // Call cmsLinkTag to link the tag to another tag
        cmsBool linkResult = cmsLinkTag(hProfile, tagSig, retrievedTagSig);
        if (!linkResult) {
            free(tagData);
            cmsCloseProfile(hProfile);
            return 0; // Error in linking tags
        }

        // Call cmsWriteTag to write the tag data back to the profile
        cmsBool writeResult = cmsWriteTag(hProfile, tagSig, tagData);
        if (!writeResult) {
            free(tagData);
            cmsCloseProfile(hProfile);
            return 0; // Error in writing tag
        }

        // Free the tag data after use
        free(tagData);
    }

    // Close the profile handle
    cmsCloseProfile(hProfile);

    return 0; // Success
}
