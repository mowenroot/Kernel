#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <memory>

// Function to safely convert fuzz input to a cmsUInt32Number
cmsUInt32Number SafeConvertToUInt32(const uint8_t* data, size_t size, size_t index) {
    if (index >= size) return 0;
    return static_cast<cmsUInt32Number>(data[index]);
}

// Function to safely convert fuzz input to a cmsUInt64Number
cmsUInt64Number SafeConvertToUInt64(const uint8_t* data, size_t size, size_t index) {
    if (index + sizeof(cmsUInt64Number) > size) return 0;
    cmsUInt64Number result = 0;
    memcpy(&result, data + index, sizeof(cmsUInt64Number));
    return result;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < sizeof(cmsUInt32Number) * 3 + sizeof(cmsUInt64Number)) return 0;

    // Initialize variables
    cmsUInt32Number intent = SafeConvertToUInt32(data, size, 0);
    cmsUInt32Number usedDirection = SafeConvertToUInt32(data, size, sizeof(cmsUInt32Number));
    cmsUInt32Number maxIntents = SafeConvertToUInt32(data, size, sizeof(cmsUInt32Number) * 2);
    cmsUInt64Number flags = SafeConvertToUInt64(data, size, sizeof(cmsUInt32Number) * 3);

    // Create a profile context
    cmsContext context = cmsCreateContext(nullptr, nullptr);
    if (!context) return 0;

    // Create a profile
    cmsHPROFILE profile = cmsCreateProfilePlaceholder(context);
    if (!profile) {
        cmsDeleteContext(context);
        return 0;
    }

    // Test cmsIsIntentSupported
    cmsBool isIntentSupported = cmsIsIntentSupported(profile, intent, usedDirection);

    // Test cmsGetSupportedIntentsTHR
    std::unique_ptr<cmsUInt32Number[]> codes(new cmsUInt32Number[maxIntents]);
    std::unique_ptr<char*[]> descriptions(new char*[maxIntents]);
    cmsUInt32Number numIntents = cmsGetSupportedIntentsTHR(context, maxIntents, codes.get(), descriptions.get());

    // Test cmsGetHeaderAttributes
    cmsGetHeaderAttributes(profile, &flags);

    // Test cmsIsMatrixShaper
    cmsBool isMatrixShaper = cmsIsMatrixShaper(profile);

    // Test cmsDetectTAC
    cmsFloat64Number tac = cmsDetectTAC(profile);

    // Clean up
    cmsCloseProfile(profile);
    cmsDeleteContext(context);

    return 0;
}
