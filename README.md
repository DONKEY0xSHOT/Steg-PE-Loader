# Steg-PE-Loader

## ⚠️ IMPORTANT: EDUCATIONAL PURPOSE ONLY ⚠️

**This project is a Proof-of-Concept (PoC) developed strictly for academic and research purposes. It is intended for use in controlled, ethical security research environments to study malware behavior and improve defensive solutions**

## Overview
This project is a toolkit for hiding and executing 32-bit Windows executables inside PNG images using Least Significant Bit (LSB) steganography and in-memory execution.

It consists of two tools:

### 1. LSB EXE Embedder

This tool embeds a 32-bit `.exe` file into a `.png` image using LSB steganography.

- **Input**: A PNG image and a 32-bit Windows executable (`.exe`)
- **Output**: A new PNG image that appears unchanged but contains the embedded executable payload

### 2. EXE Loader

This tool extracts the embedded `.exe` from the encoded PNG image and runs it directly from memory using process hollowing.

- **Input**: PNG image with an embedded `.exe`
- **Output**: The extracted executable is loaded into memory and executed without ever touching disk

## Usage

### Embedder

**Command:**
embedder.exe <input_image.png> <file_to_hide.exe>

**Example:**
embedder.exe logo.png calc.exe

### Loader

**Command:**
loader.exe <encoded_image.png>

**Example:**
loader.exe encoded.png


## How It Works

### LSB Embedding

The embedder reads the binary contents of the executable and converts it into a stream of bits. These bits are embedded into the least significant bits of the input image’s pixel data. This allows the image to appear the same (visually) while actually hiding data.

### In-Memory Execution (Process Hollowing)

The loader extracts the bitstream from the image and reconstructs the original binary data. It then launches a legitimate process (svchost.exe) in suspended mode and replaces its memory with the extracted executable. The result is execution from memory, bypassing disk writes entirely!
