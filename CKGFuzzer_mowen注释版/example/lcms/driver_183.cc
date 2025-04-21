#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely extract a double from the fuzz input
bool extractDouble(const uint8_t* data, size_t size, size_t& offset, cmsFloat64Number& value) {
    if (offset + sizeof(cmsFloat64Number) > size) return false;
    memcpy(&value, data + offset, sizeof(cmsFloat64Number));
    offset += sizeof(cmsFloat64Number);
    return true;
}

// Function to safely extract a cmsCIExyY from the fuzz input
bool extractCIExyY(const uint8_t* data, size_t size, size_t& offset, cmsCIExyY& whitePoint) {
    if (offset + sizeof(cmsCIExyY) > size) return false;
    memcpy(&whitePoint, data + offset, sizeof(cmsCIExyY));
    offset += sizeof(cmsCIExyY);
    return true;
}

// Function to safely extract an array of cmsUInt16Number from the fuzz input
bool extractAlarmCodes(const uint8_t* data, size_t size, size_t& offset, cmsUInt16Number* alarmCodes) {
    if (offset + cmsMAXCHANNELS * sizeof(cmsUInt16Number) > size) return false;
    memcpy(alarmCodes, data + offset, cmsMAXCHANNELS * sizeof(cmsUInt16Number));
    offset += cmsMAXCHANNELS * sizeof(cmsUInt16Number);
    return true;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Initialize variables
    size_t offset = 0;
    cmsFloat64Number adaptationState = 0.0;
    cmsFloat64Number tempK = 0.0;
    cmsCIExyY whitePoint = {0.0, 0.0, 0.0};
    cmsUInt16Number alarmCodes[cmsMAXCHANNELS] = {0};

    // Extract data from fuzz input
    if (!extractDouble(data, size, offset, adaptationState)) return 0;
    if (!extractCIExyY(data, size, offset, whitePoint)) return 0;
    if (!extractDouble(data, size, offset, tempK)) return 0;
    if (!extractAlarmCodes(data, size, offset, alarmCodes)) return 0;

    // Call cmsSetAdaptationStateTHR
    cmsFloat64Number prevAdaptationState = cmsSetAdaptationStateTHR(NULL, adaptationState);

    // Call cmsTempFromWhitePoint
    cmsBool tempFromWhitePointResult = cmsTempFromWhitePoint(&tempK, &whitePoint);
    if (!tempFromWhitePointResult) {
        // Handle error
        return 0;
    }

    // Call cmsSetAdaptationState
    cmsFloat64Number newAdaptationState = cmsSetAdaptationState(adaptationState);

    // Call cmsSetAlarmCodes
    cmsSetAlarmCodes(alarmCodes);

    // Call cmsWhitePointFromTemp
    cmsBool whitePointFromTempResult = cmsWhitePointFromTemp(&whitePoint, tempK);
    if (!whitePointFromTempResult) {
        // Handle error
        return 0;
    }

    // Call cmsSetAlarmCodesTHR
    cmsSetAlarmCodesTHR(NULL, alarmCodes);

    // Ensure all resources are freed and no memory leaks occur
    // Since all APIs used here do not allocate memory, no explicit deallocation is needed

    return 0;
}
