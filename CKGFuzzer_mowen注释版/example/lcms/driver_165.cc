#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely extract a cmsFloat64Number from the fuzz input
cmsFloat64Number extractFloat64(const uint8_t* data, size_t& offset, size_t size) {
    if (offset + sizeof(cmsFloat64Number) > size) {
        return 0.0; // Return a default value if not enough data
    }
    cmsFloat64Number value;
    memcpy(&value, data + offset, sizeof(cmsFloat64Number));
    offset += sizeof(cmsFloat64Number);
    return value;
}

// Function to safely extract a cmsUInt16Number array from the fuzz input
void extractAlarmCodes(const uint8_t* data, size_t& offset, size_t size, cmsUInt16Number* alarmCodes) {
    for (size_t i = 0; i < cmsMAXCHANNELS; ++i) {
        if (offset + sizeof(cmsUInt16Number) > size) {
            alarmCodes[i] = 0; // Set default value if not enough data
        } else {
            memcpy(&alarmCodes[i], data + offset, sizeof(cmsUInt16Number));
            offset += sizeof(cmsUInt16Number);
        }
    }
}

// Fuzz driver function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < sizeof(cmsFloat64Number) + cmsMAXCHANNELS * sizeof(cmsUInt16Number)) {
        return 0;
    }

    // Initialize variables
    size_t offset = 0;
    cmsFloat64Number adaptationState = extractFloat64(data, offset, size);
    cmsUInt16Number alarmCodes[cmsMAXCHANNELS];
    extractAlarmCodes(data, offset, size, alarmCodes);

    // Create a context for multi-threaded operations
    cmsContext context = cmsCreateContext(NULL, NULL);
    if (!context) {
        return 0; // Failed to create context
    }

    // Set adaptation state using THR
    cmsFloat64Number prevAdaptationStateTHR = cmsSetAdaptationStateTHR(context, adaptationState);

    // Set adaptation state without THR
    cmsFloat64Number prevAdaptationState = cmsSetAdaptationState(adaptationState);

    // Set alarm codes using THR
    cmsSetAlarmCodesTHR(context, alarmCodes);

    // Set alarm codes without THR
    cmsSetAlarmCodes(alarmCodes);

    // Set log error handler using THR
    cmsSetLogErrorHandlerTHR(context, NULL); // Use default handler

    // Clean up context
    cmsDeleteContext(context);

    return 0;
}
