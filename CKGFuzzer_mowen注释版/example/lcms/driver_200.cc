#include "lcms2.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <cmath>
#include <memory>

// Function to safely extract a double from the fuzz input
bool extractDouble(const uint8_t*& data, size_t& size, cmsFloat64Number& value) {
    if (size < sizeof(cmsFloat64Number)) return false;
    memcpy(&value, data, sizeof(cmsFloat64Number));
    data += sizeof(cmsFloat64Number);
    size -= sizeof(cmsFloat64Number);
    return true;
}

// Function to safely extract a cmsCIELab structure from the fuzz input
bool extractCIELab(const uint8_t*& data, size_t& size, cmsCIELab& lab) {
    if (size < 3 * sizeof(cmsFloat64Number)) return false;
    memcpy(&lab.L, data, sizeof(cmsFloat64Number));
    data += sizeof(cmsFloat64Number);
    memcpy(&lab.a, data, sizeof(cmsFloat64Number));
    data += sizeof(cmsFloat64Number);
    memcpy(&lab.b, data, sizeof(cmsFloat64Number));
    data += sizeof(cmsFloat64Number);
    size -= 3 * sizeof(cmsFloat64Number);
    return true;
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Ensure we have enough data for at least two cmsCIELab structures and some parameters
    if (size < 6 * sizeof(cmsFloat64Number)) return 0;

    // Extract two cmsCIELab structures from the input
    cmsCIELab lab1, lab2;
    if (!extractCIELab(data, size, lab1) || !extractCIELab(data, size, lab2)) {
        return 0;
    }

    // Extract parameters for cmsCIE2000DeltaE
    cmsFloat64Number Kl, Kc, Kh;
    if (!extractDouble(data, size, Kl) || !extractDouble(data, size, Kc) || !extractDouble(data, size, Kh)) {
        return 0;
    }

    // Call the APIs with the extracted data
    cmsFloat64Number deltaE2000 = cmsCIE2000DeltaE(&lab1, &lab2, Kl, Kc, Kh);
    cmsFloat64Number bfdDeltaE = cmsBFDdeltaE(&lab1, &lab2);
    cmsFloat64Number cie94DeltaE = cmsCIE94DeltaE(&lab1, &lab2);
    cmsFloat64Number deltaE = cmsDeltaE(&lab1, &lab2);

    // Convert Lab to LCh and back to Lab to ensure the conversion functions are called
    cmsCIELCh lch1, lch2;
    cmsLab2LCh(&lch1, &lab1);
    cmsLab2LCh(&lch2, &lab2);
    cmsCIELab convertedLab1, convertedLab2;
    cmsLCh2Lab(&convertedLab1, &lch1);
    cmsLCh2Lab(&convertedLab2, &lch2);

    // Ensure the converted values are close to the original values
    if (std::abs(convertedLab1.L - lab1.L) > 1e-6 ||
        std::abs(convertedLab1.a - lab1.a) > 1e-6 ||
        std::abs(convertedLab1.b - lab1.b) > 1e-6 ||
        std::abs(convertedLab2.L - lab2.L) > 1e-6 ||
        std::abs(convertedLab2.a - lab2.a) > 1e-6 ||
        std::abs(convertedLab2.b - lab2.b) > 1e-6) {
        return 0; // Conversion failed, but we don't treat it as an error in fuzzing
    }

    return 0;
}
