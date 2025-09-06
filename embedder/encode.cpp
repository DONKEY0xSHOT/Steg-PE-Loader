#include "encode.h"

void embedBits(std::vector<unsigned char>& image, const std::vector<unsigned char>& dataToEmbed) {
    if (dataToEmbed.size() > image.size()) {
        throw std::runtime_error("Image too small for embedding");
    }

    for (size_t bitIndex = 0; bitIndex < dataToEmbed.size(); ++bitIndex) {

        // Get the LSB using bitwise AND with 00000001
        unsigned char bitToHide = dataToEmbed[bitIndex] & 1;

        // Read the current byte from the image
        unsigned char originalByte = image[bitIndex];

        // Clear the byte's LSB using bitwise AND with 11111110 (0xFE)
        unsigned char byteWithClearedLSB = originalByte & 0xFE;

        // Set the LSB to the bit we want to hide
        unsigned char modifiedByte = byteWithClearedLSB | bitToHide;

        image[bitIndex] = modifiedByte;
    }

}

std::vector<unsigned char> fileToBits(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file) throw std::runtime_error("File not found.");

    std::vector<unsigned char> buffer(std::istreambuf_iterator<char>(file), {});
    std::vector<unsigned char> bits;

    // Add 32-bit file size header
    uint32_t bitSize = buffer.size() * 8;
    for (int i = 31; i >= 0; --i) {
        bits.push_back((bitSize >> i) & 1);
    }

    // Convert each byte to 8 bits
    for (unsigned char byte : buffer) {
        for (int i = 7; i >= 0; --i) {
            bits.push_back((byte >> i) & 1);
        }
    }

    return bits;
}