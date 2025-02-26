---
title: "Aliyun CTF 2025 - easy cuda rev"
date: 2025-02-24 23:18:00 +0700
categories: "RE"
tags: [Writeup]
---

# Easy Cuda Rev
**Challenge Description(English translated):**
Recently, inspired by DeepSeek's direct use of PTX assembly to write optimized portions of cuda code, a simple cuda inverse question was designed to allow the contestants to learn PTX assembly and come out way ahead!

(The challenge file is available on my Github repo [HERE](https://github.com/nguyenthienanh05/Aliyun-CTF-2025).

Firstly, I use IDA to analyze the given file of the challenge:
```c
unsigned __int64 __fastcall cuda_encrypt(unsigned __int8 *a1, int a2, unsigned __int8 a3)
{
  int v3; // eax
  unsigned __int8 *v6; // [rsp+18h] [rbp-28h] BYREF
  __int64 v7; // [rsp+20h] [rbp-20h] BYREF
  int v8; // [rsp+28h] [rbp-18h]
  __int64 v9; // [rsp+2Ch] [rbp-14h] BYREF
  int v10; // [rsp+34h] [rbp-Ch]
  unsigned __int64 v11; // [rsp+38h] [rbp-8h]

  v11 = __readfsqword(0x28u);
  cudaMalloc<unsigned char>(&v6, a2);
  cudaMemcpy(v6, a1, a2, 1LL);
  dim3::dim3((dim3 *)&v9, 0x100u, 1u, 1u);
  v3 = a2 + 255;
  if ( a2 + 255 < 0 )
    v3 = a2 + 510;
  dim3::dim3((dim3 *)&v7, v3 >> 8, 1u, 1u);
  if ( !(unsigned int)_cudaPushCallConfiguration(v7, v8, v9, v10, 0, 0LL) )
    encrypt_kernel(v6, a3);
  cudaMemcpy(a1, v6, a2, 2LL);
  cudaFree(v6);
  return v11 - __readfsqword(0x28u);
}
```
We see that int the `encrypt_kernel()` we see this:
```c
unsigned __int64 __fastcall encrypt_kernel(unsigned __int8 *a1, char a2)
{
  return __device_stub__Z14encrypt_kernelPhh(a1, a2);
}
```
This mean that the PTX Assembly of Cuda cannot be disassembled and read by IDA. After searching, I found the using the `nvidia-cuda-toolkit` we can dump the disassembled PTX Assembly by using `cuobjdump easy_cuda -sass -ptx`. After doing that and some cleaning up, you'll get the PTX Assembly instructions like this [LINK](https://github.com/nguyenthienanh05/Aliyun-CTF-2025/blob/main/encrypt.asm)

The we start to analyze the PTX ASSEMBLY, we see that it performs totally 5 transformations on the each chunk of 256 bytes simultaneously. I've translated the PTX Assembly of the first transformation into this:
```cpp
const int key = 0xAC;
int T[] = {
    99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 
    215, 171, 118, 202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 
    162, 175, 156, 164, 114, 192, 183, 253, 147, 38, 54, 63, 247,
    204, 52, 165, 229, 241, 113, 216, 49, 21, 4, 199, 35, 195, 24, 
    150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117, 9, 131, 44, 26, 
    27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132, 83, 209, 0, 
    237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 208, 239, 
    170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168, 81, 
    163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 
    210, 205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 
    25, 115, 96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 
    11, 219, 224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 
    228, 121, 231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 
    122, 174, 8, 186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 
    189, 139, 138, 112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 
    193, 29, 158, 225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 
    206, 85, 40, 223, 140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 
    176, 84, 187, 22
};
int main() { 
    for (int i = 0; i < 1000; i++) {
        int temp = VAR_FILE_INPUT[i] ^ key + (i * 73);
        int res = ((temp & 240) >> 4) | (temp << 4);
        for (int k = 0; k < 5; k++) {
            for (int j = 0; j < 10485760; i++) {
                res &= 0xFF;
                int rs24 = T[res] << 4 | T[res] >> 4;
                res ^= rs24;
            }
        }
        VAR_FILE_INPUT[i] = res;
    }
}
```
And the second transformation is like this for each chunk:
```cpp
    const int key = 0xAC;
    for (int i = 255; i >= 0; j++)
        VAR_FILE_INPUT[i] ^= VAR_FILE_INPUT[(i + 1) % 256] ^ key;
```
The third transformation is swapping in pairs and the first pair is index 0 and 1. The third transfromation is also the same but the first pair has the index 1 and 2, the last element is swapped with the first element. The fifth transformtation is the TEA-like encryption:
```cpp
#define ROUNDS 10485760
void code(uint32_t v[2], const uint32_t k[4]) {
    uint32_t v0 = v[0], v1 = v[1];
    uint32_t sum = 0;
    const uint32_t delta = 0x9e3779b9;
    
    for (uint32_t i = 0; i < ROUNDS; i++) {
        sum += delta;
        v0 += ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]);
        v1 += ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]);
    }
    
    v[0] = v0;
    v[1] = v1;

    printf("Final sum: 0x%08x\n", sum);
}
```
The final transformation is the taking the byte and xoring with its index in the chunk.
So from those information, we can start to reverse it.
Firstly, I'm gonna undo the transformation of part 6, and part 5 by using a cpp code like this:
```cpp
#include <iostream>
#include <fstream>

using namespace std;

#define ROUNDS 10485760
// Convert a single hex digit to its integer value.
uint8_t hexVal(char c) {
    if ('0' <= c && c <= '9')
        return c - '0';
    if ('a' <= c && c <= 'f')
        return c - 'a' + 10;
    if ('A' <= c && c <= 'F')
        return c - 'A' + 10;
    return 0;
}

// Convert a hex string to a byte array.
void hexStringToBytes(const char *hex, uint8_t **out, size_t *outLen) {
    size_t len = strlen(hex);
    if (len % 2 != 0) {
        *out = NULL;
        *outLen = 0;
        return;
    }
    *outLen = len / 2;
    *out = (uint8_t *) malloc(*outLen);
    for (size_t i = 0; i < *outLen; i++) {
        (*out)[i] = (hexVal(hex[2*i]) << 4) | hexVal(hex[2*i + 1]);
    }
}

void decode(uint32_t v[2], const uint32_t k[4]) {
    uint32_t v0 = v[0], v1 = v[1];
    uint32_t sum = 0x13a00000;
    const uint32_t delta = 0x9e3779b9;
    
    for (uint32_t i = 0; i < ROUNDS; i++) {
        v1 -= ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]);
        v0 -= ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]);
        sum -= delta;
    }
    
    v[0] = v0;
    v[1] = v1;
}

int main(void) {
    FILE* fp = freopen("flag_enc", "rb", stdin);
    
    // Get file size
    fseek(fp, 0, SEEK_END);
    size_t fileSize = 169472;

    cout << fileSize << endl;
    fseek(fp, 0, SEEK_SET);

    uint8_t* flag_bytes = (uint8_t*)malloc(fileSize);

    
    size_t bytesRead = fread(flag_bytes, 1, fileSize, fp);
    if (bytesRead != fileSize) {
        fprintf(stderr, "Failed to read entire file\n");
        free(flag_bytes);
        return 1;
    }

    for (int i = 0; i < fileSize; i++) {
        *(flag_bytes + i) ^= i;
    }
    

    int idx = 0;
    for (int i = 0; i < fileSize; i += 8) {
        uint32_t v0 = (flag_bytes[i] << 0) | (flag_bytes[i + 1] << 8) | (flag_bytes[i + 2] << 16) | (flag_bytes[i + 3] << 24);
        uint32_t v1 = (flag_bytes[i + 4] << 0) | (flag_bytes[i + 5] << 8) | (flag_bytes[i + 6] << 16) | (flag_bytes[i + 7] << 24);
        uint32_t v[2] = { v0, v1 };
        uint32_t key[4] = { 0xa341316c, 0xc8013ea4, 0x3c6ef372, 0x14292967 };
        decode(v, key);
        idx += 2;
        printf("%08x%08x", v[0], v[1]);
    }
    return 0;
}
```
Then copy input to a .txt file I use this python code to process it into a bytes file:
```python
with open('parts_byte.txt', 'r') as f:
    a = f.read()
a = bytes.fromhex(a)
chunks = [a[i:i+4] for i in range(0, len(a), 4)]

part4 = [chunk[::-1] for chunk in chunks]
a = b''.join(part4)

with open('final_bytes', 'wb') as f:
    f.write(a)
```

Then I reverse reverse the final parts and get the flag
```python
VAR_FILE_INPUT = open('final_bytes', 'rb').read().strip()
output = b''

input_file = list(VAR_FILE_INPUT)

for i in range(0, 662):
    VAR_FILE_INPUT = input_file[256*i:256*(i + 1)]

    for i in range(1, len(VAR_FILE_INPUT) - 1, 2):
        VAR_FILE_INPUT[i], VAR_FILE_INPUT[i + 1] = VAR_FILE_INPUT[i + 1], VAR_FILE_INPUT[i]
    VAR_FILE_INPUT[0], VAR_FILE_INPUT[-1] = VAR_FILE_INPUT[-1], VAR_FILE_INPUT[0]

    for i in range(0, len(VAR_FILE_INPUT), 2):
        VAR_FILE_INPUT[i], VAR_FILE_INPUT[i + 1] = VAR_FILE_INPUT[i + 1], VAR_FILE_INPUT[i]

    VAR_CHAR_KEY = 0xac
    br = 256 # number of blocks

    r248 = 0
    for i in range(0, len(VAR_FILE_INPUT), br):
        for j in range(br - 1, -1, -1):
            VAR_FILE_INPUT[i + j] ^= VAR_FILE_INPUT[i + (j + 1) % br] ^ 0xac

    def ror8(value, shift):
        value &= 0xFF
        return ((value >> shift) | (value << (8 - shift))) & 0xFF

    def rol8(value, shift):
        value &= 0xFF
        return ((value << shift) | (value >> (8 - shift))) & 0xFF

    T = [99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118, 202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192, 183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21, 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117, 9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132, 83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168, 81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210, 205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115, 96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121, 231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138, 112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22, 82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251, 124, 227, 57, 130, 155, 47, 255, 135, 52, 142, 67, 68, 196, 222, 233, 203, 84, 123, 148, 50, 166, 194, 35, 61, 238, 76, 149, 11, 66, 250, 195, 78, 8, 46, 161, 102, 40, 217, 36, 178, 118, 91, 162, 73, 109, 139, 209, 37, 114, 248, 246, 100, 134, 104, 152, 22, 212, 164, 92, 204, 93, 101, 182, 146, 108, 112, 72, 80, 253, 237, 185, 218, 94, 21, 70, 87, 167, 141, 157, 132, 144, 216, 171, 0, 140, 188, 211, 10, 247, 228, 88, 5, 184, 179, 69, 6, 208, 44, 30, 143, 202, 63, 15, 2, 193, 175, 189, 3, 1, 19, 138, 107, 58, 145, 17, 65, 79, 103, 220, 234, 151, 242, 207, 206, 240, 180, 230, 115, 150, 172, 116, 34, 231, 173, 53, 133, 226, 249, 55, 232, 28, 117, 223, 110, 71, 241, 26, 113, 29, 41, 197, 137, 111, 183, 98, 14, 170, 24, 190, 27, 252, 86, 62, 75, 198, 210, 121, 32, 154, 219, 192, 254, 120, 205, 90, 244, 31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236, 95, 96, 81, 127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239, 160, 224, 59, 77, 174, 42, 245, 176, 200, 235, 187, 60, 131, 83, 153, 97, 23, 43, 4, 126, 186, 119, 214, 38, 225, 105, 20, 99, 85, 33, 12, 125]
    revT = [-1 for i in range(256)]
    for i in range(256):
        revT[T[i]] = i

    VAR_FILE_INPUT = VAR_FILE_INPUT
    from tqdm import tqdm
    # ===== LAST DANCE =====
    table = [44, 17, 179, 78, 29, 236, 55, 93, 121, 12, 104, 105, 207, 210, 197, 26, 66, 182, 90, 162, 147, 180, 2, 141, 38, 225, 196, 37, 6, 229, 231, 253, 31, 0, 34, 20, 91, 40, 161, 103, 164, 192, 97, 36, 76, 251, 133, 60, 219, 149, 198, 99, 206, 214, 101, 19, 94, 112, 193, 67, 166, 22, 240, 254, 62, 215, 25, 174, 11, 13, 136, 230, 204, 194, 87, 122, 223, 118, 221, 244, 68, 145, 43, 209, 41, 4, 48, 199, 42, 80, 61, 150, 252, 50, 120, 228, 59, 238, 181, 152, 113, 46, 57, 208, 74, 16, 249, 82, 108, 102, 138, 134, 63, 117, 235, 137, 144, 246, 195, 52, 139, 47, 143, 98, 70, 84, 124, 185, 154, 23, 114, 242, 92, 73, 33, 186, 250, 127, 79, 72, 8, 237, 1, 128, 248, 110, 216, 205, 148, 167, 53, 28, 69, 232, 65, 239, 64, 88, 226, 123, 243, 247, 116, 106, 24, 89, 96, 168, 131, 132, 170, 202, 126, 220, 255, 191, 83, 201, 178, 135, 172, 27, 10, 86, 18, 211, 54, 51, 100, 14, 7, 85, 218, 224, 119, 160, 183, 188, 163, 245, 171, 203, 153, 200, 227, 130, 234, 187, 81, 189, 222, 165, 129, 30, 5, 77, 184, 15, 75, 115, 140, 107, 71, 158, 156, 217, 155, 175, 157, 169, 151, 146, 39, 177, 176, 173, 49, 125, 35, 9, 111, 142, 241, 95, 32, 233, 159, 45, 56, 212, 213, 21, 58, 109, 3, 190]
    rtable = [-1 for i in range(256)]
    for i in range(256):
        rtable[table[i]] = i

    for i in range(len(VAR_FILE_INPUT)):
        curr = VAR_FILE_INPUT[i]
        for _ in range(5):
            curr = rtable[curr]
        curr = rol8(curr, 4)
        curr ^= ((i * 73) + VAR_CHAR_KEY) & 255
        VAR_FILE_INPUT[i] = curr

    output += bytes(VAR_FILE_INPUT)
open('flag.png', 'wb').write(output)
```
This is the flag:
![Flag result](https://raw.githubusercontent.com/nguyenthienanh05/nguyenthienanh05.github.io/main/assets/img/flag.png)
