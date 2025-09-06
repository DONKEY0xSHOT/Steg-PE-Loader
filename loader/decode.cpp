#include "decode.h"

// Helper function to get the length of the embedded data
uint32_t extractLengthFromImage(const std::vector<unsigned char>& imageData) {
    uint32_t bitLength = 0;

    for (int bitPosition = 0; bitPosition < 32; ++bitPosition) {

        // Shift existing bits left for the next bit
        bitLength <<= 1;

        // Read the LSB of the current image byte and add it to bitLength
        unsigned char currentLSB = imageData[bitPosition] & 1;
        bitLength = bitLength | currentLSB;
    }

    return bitLength;
}

// Get the embedded data from the image using the bit length read from the header
std::vector<unsigned char> extractFileDataFromImage(const std::vector<unsigned char>& imageData, uint32_t dataBitLength) {
    std::vector<unsigned char> extractedBits;

    // Start after the first 32 bits (used for length) & read the next 'dataBitLength' bits
    for (uint32_t i = 0; i < dataBitLength; ++i) {

        // Extract LSB from image byte using a bitwise AND operation
        unsigned char bit = imageData[32 + i] & 1;
        extractedBits.push_back(bit);
    }

    std::vector<unsigned char> fileBytes;

    // Convert every 8 bits into one byte
    for (size_t i = 0; i < extractedBits.size(); i += 8) {
        unsigned char reconstructedByte = 0;

        for (int bitIndex = 0; bitIndex < 8; ++bitIndex) {

            // Shift left for next bit
            reconstructedByte <<= 1;

            // Add next bit
            unsigned char currentBit = extractedBits[i + bitIndex] & 1;
            reconstructedByte = reconstructedByte | currentBit;
        }

        fileBytes.push_back(reconstructedByte);
    }

    return fileBytes;
}