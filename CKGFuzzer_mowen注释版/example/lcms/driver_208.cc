#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Function to safely extract a float from the fuzz input
float safe_extract_float(const uint8_t* data, size_t& offset, size_t size) {
    if (offset + sizeof(float) > size) {
        return 0.0f; // Return a default value if not enough data
    }
    float value;
    memcpy(&value, data + offset, sizeof(float));
    offset += sizeof(float);
    return value;
}

// Function to safely extract an integer from the fuzz input
int safe_extract_int(const uint8_t* data, size_t& offset, size_t size) {
    if (offset + sizeof(int) > size) {
        return 0; // Return a default value if not enough data
    }
    int value;
    memcpy(&value, data + offset, sizeof(int));
    offset += sizeof(int);
    return value;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data to proceed
    if (size < 6 * sizeof(float) + 3 * sizeof(int)) {
        return 0;
    }

    // Initialize variables
    size_t offset = 0;
    cmsCIELab Lab1, Lab2;
    cmsCIELCh LCh1, LCh2;
    cmsFloat64Number deltaE2000, deltaEBFD, deltaE94, deltaE;

    // Extract Lab values from fuzz input
    Lab1.L = safe_extract_float(data, offset, size);
    Lab1.a = safe_extract_float(data, offset, size);
    Lab1.b = safe_extract_float(data, offset, size);

    Lab2.L = safe_extract_float(data, offset, size);
    Lab2.a = safe_extract_float(data, offset, size);
    Lab2.b = safe_extract_float(data, offset, size);

    // Extract additional parameters for cmsCIE2000DeltaE
    cmsFloat64Number Kl = safe_extract_float(data, offset, size);
    cmsFloat64Number Kc = safe_extract_float(data, offset, size);
    cmsFloat64Number Kh = safe_extract_float(data, offset, size);

    // Call cmsCIE2000DeltaE
    deltaE2000 = cmsCIE2000DeltaE(&Lab1, &Lab2, Kl, Kc, Kh);

    // Call cmsBFDdeltaE
    deltaEBFD = cmsBFDdeltaE(&Lab1, &Lab2);

    // Convert Lab to LCh
    cmsLab2LCh(&LCh1, &Lab1);
    cmsLab2LCh(&LCh2, &Lab2);

    // Convert LCh back to Lab
    cmsLCh2Lab(&Lab1, &LCh1);
    cmsLCh2Lab(&Lab2, &LCh2);

    // Call cmsCIE94DeltaE
    deltaE94 = cmsCIE94DeltaE(&Lab1, &Lab2);

    // Call cmsDeltaE
    deltaE = cmsDeltaE(&Lab1, &Lab2);

    // Ensure all calculations are valid
    if (deltaE2000 < 0 || deltaEBFD < 0 || deltaE94 < 0 || deltaE < 0) {
        return 0; // Invalid result, exit early
    }

    // No need to free any resources as we used stack-allocated structures
    return 0;
}
