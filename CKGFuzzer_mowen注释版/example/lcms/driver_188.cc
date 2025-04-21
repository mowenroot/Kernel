#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to check if the input size is sufficient for the required operations
bool isInputSizeValid(size_t size, size_t requiredSize) {
    return size >= requiredSize;
}

// Function to safely copy data from the fuzz input to a buffer
void safeCopy(void* dest, const uint8_t* src, size_t size) {
    if (dest && src && size > 0) {
        memcpy(dest, src, size);
    }
}

// Function to safely convert fuzz input to a specific type
template <typename T>
T safeConvert(const uint8_t* data, size_t& offset, size_t size) {
    if (offset + sizeof(T) > size) {
        return T();
    }
    T value;
    memcpy(&value, data + offset, sizeof(T));
    offset += sizeof(T);
    return value;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for the operations
    if (!isInputSizeValid(size, 6 * sizeof(cmsUInt16Number))) {
        return 0;
    }

    // Initialize variables
    cmsUInt16Number encodedXYZ[3];
    cmsCIEXYZ floatXYZ;
    cmsCIELab floatLab;
    cmsCIExyY floatxyY;
    cmsCIEXYZ whitePoint;

    // Offset for reading data
    size_t offset = 0;

    // Convert fuzz input to encoded XYZ values
    for (int i = 0; i < 3; ++i) {
        encodedXYZ[i] = safeConvert<cmsUInt16Number>(data, offset, size);
    }

    // Convert encoded XYZ to floating-point XYZ
    cmsXYZEncoded2Float(&floatXYZ, encodedXYZ);

    // Convert floating-point XYZ to Lab using a default white point
    cmsXYZ2Lab(nullptr, &floatLab, &floatXYZ);

    // Convert floating-point XYZ to xyY
    cmsXYZ2xyY(&floatxyY, &floatXYZ);

    // Convert floating-point XYZ back to encoded XYZ
    cmsUInt16Number encodedXYZ2[3];
    cmsFloat2XYZEncoded(encodedXYZ2, &floatXYZ);

    // Convert encoded Lab values to floating-point format
    cmsLabEncoded2Float(&floatLab, encodedXYZ);

    // Convert encoded Lab values to floating-point format using V2
    cmsLabEncoded2FloatV2(&floatLab, encodedXYZ);

    // Ensure all allocated resources are freed
    // (No dynamic memory allocation in this example, so no need to free anything)

    return 0;
}
