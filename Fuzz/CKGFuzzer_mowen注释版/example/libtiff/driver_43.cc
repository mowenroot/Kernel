#include <tiffio.h>
#include <tiffio.hxx>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <sstream> // Include for std::istringstream

// Function to create a TIFF object from fuzz input data
TIFF* createTIFFFromFuzzInput(const uint8_t* data, size_t size) {
    // Convert fuzz input to a string
    std::string fuzzInput(reinterpret_cast<const char*>(data), size);
    std::istringstream s(fuzzInput); // Use std::istringstream instead of std::stringstream

    // Create a TIFF stream in memory
    TIFF* tif = TIFFStreamOpen("MemTIFF", &s); // Pass the address of the istringstream
    if (!tif) {
        TIFFErrorExt(0, "createTIFFFromFuzzInput", "Failed to create TIFF stream from fuzz input");
    }
    return tif;
}

// Function to free resources allocated for the TIFF object
void freeTIFFResources(TIFF* tif) {
    if (tif) {
        TIFFClose(tif);
    }
}

// Main fuzzing function
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    TIFF* tif = nullptr;
    uint32 row = 0;
    uint16 sample = 0;
    void* buf = nullptr;
    FILE* outputFile = nullptr;

    // Ensure the input size is sufficient for basic operations
    if (size < sizeof(uint32) + sizeof(uint16)) {
        return 0;
    }

    // Extract row and sample from fuzz input
    row = *((uint32*)data);
    sample = *((uint16*)(data + sizeof(uint32)));

    // Create a TIFF object from fuzz input
    tif = createTIFFFromFuzzInput(data, size);
    if (!tif) {
        return 0;
    }

    // Allocate buffer for reading/writing scanlines
    buf = malloc(TIFFScanlineSize(tif));
    if (!buf) {
        TIFFErrorExt(0, "LLVMFuzzerTestOneInput", "Failed to allocate buffer for scanline");
        freeTIFFResources(tif);
        return 0;
    }

    // Open an output file for TIFFPrintDirectory
    outputFile = fopen("output_file", "w");
    if (!outputFile) {
        TIFFErrorExt(0, "LLVMFuzzerTestOneInput", "Failed to open output file");
        free(buf);
        freeTIFFResources(tif);
        return 0;
    }

    // Call TIFFReadScanline
    if (TIFFReadScanline(tif, buf, row, sample) == -1) {
        TIFFWarningExt(0, "LLVMFuzzerTestOneInput", "TIFFReadScanline failed");
    }

    // Call TIFFWriteScanline
    if (TIFFWriteScanline(tif, buf, row, sample) == -1) {
        TIFFWarningExt(0, "LLVMFuzzerTestOneInput", "TIFFWriteScanline failed");
    }

    // Call TIFFFlushData
    if (TIFFFlushData(tif) == 0) {
        TIFFWarningExt(0, "LLVMFuzzerTestOneInput", "TIFFFlushData failed");
    }

    // Call TIFFPrintDirectory
    TIFFPrintDirectory(tif, outputFile, 0);

    // Close the output file
    fclose(outputFile);

    // Free allocated resources
    free(buf);
    freeTIFFResources(tif);

    return 0;
}
