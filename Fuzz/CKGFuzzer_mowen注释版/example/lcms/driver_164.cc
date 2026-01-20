#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely extract a 32-bit integer from the fuzz input
cmsUInt32Number ExtractUInt32(const uint8_t* data, size_t& offset, size_t size) {
    if (offset + sizeof(cmsUInt32Number) > size) {
        return 0; // Return a default value if not enough data
    }
    cmsUInt32Number value = *reinterpret_cast<const cmsUInt32Number*>(data + offset);
    offset += sizeof(cmsUInt32Number);
    return value;
}

// Function to safely extract a 64-bit integer from the fuzz input
cmsUInt64Number ExtractUInt64(const uint8_t* data, size_t& offset, size_t size) {
    if (offset + sizeof(cmsUInt64Number) > size) {
        return 0; // Return a default value if not enough data
    }
    cmsUInt64Number value = *reinterpret_cast<const cmsUInt64Number*>(data + offset);
    offset += sizeof(cmsUInt64Number);
    return value;
}

// Function to safely extract a double from the fuzz input
cmsFloat64Number ExtractFloat64(const uint8_t* data, size_t& offset, size_t size) {
    if (offset + sizeof(cmsFloat64Number) > size) {
        return 0.0; // Return a default value if not enough data
    }
    cmsFloat64Number value = *reinterpret_cast<const cmsFloat64Number*>(data + offset);
    offset += sizeof(cmsFloat64Number);
    return value;
}

// Function to safely extract an array of 16-bit integers from the fuzz input
void ExtractUInt16Array(const uint8_t* data, size_t& offset, size_t size, cmsUInt16Number* array, size_t array_size) {
    for (size_t i = 0; i < array_size; ++i) {
        if (offset + sizeof(cmsUInt16Number) > size) {
            array[i] = 0; // Set remaining elements to default value if not enough data
            continue;
        }
        array[i] = *reinterpret_cast<const cmsUInt16Number*>(data + offset);
        offset += sizeof(cmsUInt16Number);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < (sizeof(cmsUInt32Number) * 3 + sizeof(cmsUInt64Number) + sizeof(cmsFloat64Number) + sizeof(cmsUInt16Number) * cmsMAXCHANNELS)) {
        return 0; // Not enough data to proceed
    }

    // Create a new profile
    cmsHPROFILE hProfile = cmsCreateProfilePlaceholder(NULL);
    if (!hProfile) {
        return 0; // Failed to create profile
    }

    // Extract data from fuzz input
    size_t offset = 0;
    cmsUInt32Number manufacturer = ExtractUInt32(data, offset, size);
    cmsUInt64Number attributes = ExtractUInt64(data, offset, size);
    cmsFloat64Number adaptationState = ExtractFloat64(data, offset, size);
    cmsUInt16Number alarmCodes[cmsMAXCHANNELS];
    ExtractUInt16Array(data, offset, size, alarmCodes, cmsMAXCHANNELS);
    cmsUInt32Number flags = ExtractUInt32(data, offset, size);
    cmsUInt32Number model = ExtractUInt32(data, offset, size);

    // Set profile header manufacturer
    cmsSetHeaderManufacturer(hProfile, manufacturer);

    // Set profile header attributes
    cmsSetHeaderAttributes(hProfile, attributes);

    // Set adaptation state
    cmsSetAdaptationState(adaptationState);

    // Set alarm codes
    cmsSetAlarmCodes(alarmCodes);

    // Set profile header flags
    cmsSetHeaderFlags(hProfile, flags);

    // Set profile header model
    cmsSetHeaderModel(hProfile, model);

    // Clean up
    cmsCloseProfile(hProfile);

    return 0;
}
