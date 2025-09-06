#pragma once
#include <vector>
#include "Windows.h"
#include<Windows.h>
#include<stdio.h>
#include<iostream>
#pragma comment(lib, "ntdll.lib")
using namespace std;

typedef LONG(NTAPI* pfnZwUnmapViewOfSection)(HANDLE, PVOID);
int runExecutableInMemory(std::vector<unsigned char> data);