#pragma once
#include "loadpng.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <bitset>

void embedBits(std::vector<unsigned char>& image, const std::vector<unsigned char>& dataToEmbed);
std::vector<unsigned char> fileToBits(const std::string& filepath);