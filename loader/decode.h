#pragma once
#include "loadpng.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <bitset>

uint32_t extractLengthFromImage(const std::vector<unsigned char>& imageData);
std::vector<unsigned char> extractFileDataFromImage(const std::vector<unsigned char>& imageData, uint32_t dataBitLength);