#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely extract a uint32_t from the fuzz input
uint32_t extractUint32(const uint8_t* data, size_t& offset, size_t size) {
    if (offset + sizeof(uint32_t) > size) {
        return 0; // Return 0 if not enough data
    }
    uint32_t value = *reinterpret_cast<const uint32_t*>(data + offset);
    offset += sizeof(uint32_t);
    return value;
}

// Function to safely extract a cmsTagSignature from the fuzz input
cmsTagSignature extractTagSignature(const uint8_t* data, size_t& offset, size_t size) {
    if (offset + sizeof(cmsTagSignature) > size) {
        return (cmsTagSignature)0; // Return a default value if not enough data
    }
    cmsTagSignature value = *reinterpret_cast<const cmsTagSignature*>(data + offset);
    offset += sizeof(cmsTagSignature);
    return value;
}

// Function to safely extract a cmsHPROFILE from the fuzz input
cmsHPROFILE extractHProfile(const uint8_t* data, size_t& offset, size_t size) {
    if (offset + sizeof(cmsHPROFILE) > size) {
        return nullptr; // Return nullptr if not enough data
    }
    cmsHPROFILE value = *reinterpret_cast<const cmsHPROFILE*>(data + offset);
    offset += sizeof(cmsHPROFILE);
    return value;
}

// Function to safely extract a cmsContext from the fuzz input
cmsContext extractContext(const uint8_t* data, size_t& offset, size_t size) {
    if (offset + sizeof(cmsContext) > size) {
        return nullptr; // Return nullptr if not enough data
    }
    cmsContext value = *reinterpret_cast<const cmsContext*>(data + offset);
    offset += sizeof(cmsContext);
    return value;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    size_t offset = 0;
    cmsContext context = nullptr;
    cmsHPROFILE profile = nullptr;
    cmsHTRANSFORM transform = nullptr;
    void* tagData = nullptr;

    // Extract necessary inputs from fuzz data
    uint32_t flags = extractUint32(data, offset, size);
    cmsTagSignature tagSig = extractTagSignature(data, offset, size);
    cmsHPROFILE inputProfile = extractHProfile(data, offset, size);
    cmsHPROFILE outputProfile = extractHProfile(data, offset, size);
    cmsHPROFILE proofingProfile = extractHProfile(data, offset, size);
    cmsContext newContext = extractContext(data, offset, size);

    // Create a new context
    context = cmsCreateContext(nullptr, nullptr);
    if (!context) {
        return 0; // Failed to create context
    }

    // Duplicate the context
    newContext = cmsDupContext(context, nullptr);
    if (!newContext) {
        cmsDeleteContext(context);
        return 0; // Failed to duplicate context
    }

    // Create a proofing transform
    transform = cmsCreateProofingTransformTHR(newContext, inputProfile, 0, outputProfile, 0, proofingProfile, 0, 0, flags);
    if (!transform) {
        cmsDeleteContext(newContext);
        cmsDeleteContext(context);
        return 0; // Failed to create transform
    }

    // Read a tag from the profile
    tagData = cmsReadTag(profile, tagSig);
    if (!tagData) {
        cmsDeleteTransform(transform);
        cmsDeleteContext(newContext);
        cmsDeleteContext(context);
        return 0; // Failed to read tag
    }

    // Clean up resources
    cmsDeleteTransform(transform);
    cmsDeleteContext(newContext);
    cmsDeleteContext(context);

    return 0;
}
