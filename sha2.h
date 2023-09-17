#pragma once

#include <string>
#include <stdio.h>
#include <iostream>
#include <iomanip>
#include <cstdint>
#include <sstream>

//Macro for SHA384 and SHA512
#define Ch(x, y, z) ((x & y) ^ (~x & z))
#define Maj(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define RotR(x, n) ((x >> n) | (x << ((sizeof(x) << 3) - n)))
#define Sig0(x) ((RotR(x, 28)) ^ (RotR(x,34)) ^  (RotR(x, 39)))
#define Sig1(x) ((RotR(x, 14)) ^ (RotR(x,18)) ^ (RotR(x, 41)))
#define sig0(x) (RotR(x, 1) ^ RotR(x, 8) ^ (x >> 7))
#define sig1(x) (RotR(x, 19) ^ RotR(x, 61) ^ (x >> 6))

typedef unsigned __int8  uint8_t;
typedef unsigned __int32 uint32_t;
typedef unsigned __int64 uint64_t;
typedef unsigned long long uint64;

#ifndef _SHA_256
#define _SHA_256


class SHA256
{
public:
    /// split into 64 byte blocks (=> 512 bits), hash is 32 bytes long
    enum { BlockSize = 512 / 8, HashBytes = 32 };

    /// Create hash as well as reset()
    SHA256();
    SHA256(const std::string text);
    SHA256(const void* data, size_t numBytes);

    /// add arbitrary number of bytes
    void add(const void* data, size_t numBytes);

    /// return latest hash as 64 hex characters
    std::string getHash();
    /// return latest hash as bytes
    void getHash(unsigned char buffer[HashBytes]);

    /// restart
    void reset();

private:
    /// process 64 bytes
    void processBlock(const void* data);
    /// process everything left in the internal buffer
    void processBuffer();

    /// size of processed data in bytes
    uint64_t m_numBytes;
    /// valid bytes in m_buffer
    size_t   m_bufferSize;
    /// bytes not processed yet
    uint8_t  m_buffer[BlockSize];

    enum { HashValues = HashBytes / 4 };
    /// hash, stored as integers
    uint32_t m_hash[HashValues];
};

SHA256::SHA256()
{
    reset();
}

SHA256::SHA256(const std::string text) {
    reset();
    add(text.c_str(), text.size());
}

SHA256::SHA256(const void* data, size_t numBytes) {
    reset();
    add(data, numBytes);
}

/// restart
void SHA256::reset()
{
    m_numBytes = 0;
    m_bufferSize = 0;

    // according to RFC 1321
    // "These words were obtained by taking the first thirty-two bits of the
    //  fractional parts of the square roots of the first eight prime numbers"
    m_hash[0] = 0x6a09e667;
    m_hash[1] = 0xbb67ae85;
    m_hash[2] = 0x3c6ef372;
    m_hash[3] = 0xa54ff53a;
    m_hash[4] = 0x510e527f;
    m_hash[5] = 0x9b05688c;
    m_hash[6] = 0x1f83d9ab;
    m_hash[7] = 0x5be0cd19;

#ifdef SHA2_224_SEED_VECTOR
    // if you want SHA2-224 instead then use these seeds
    // and throw away the last 32 bits of getHash
    m_hash[0] = 0xc1059ed8;
    m_hash[1] = 0x367cd507;
    m_hash[2] = 0x3070dd17;
    m_hash[3] = 0xf70e5939;
    m_hash[4] = 0xffc00b31;
    m_hash[5] = 0x68581511;
    m_hash[6] = 0x64f98fa7;
    m_hash[7] = 0xbefa4fa4;
#endif
}


namespace {
    inline uint32_t rotate(uint32_t a, uint32_t c) {
        return (a >> c) | (a << (32 - c));
    }

    inline uint32_t swap(uint32_t x) {
#if defined(__GNUC__) || defined(__clang__)
        return __builtin_bswap32(x);
#endif
#ifdef MSC_VER
        return _byteswap_ulong(x);
#endif

        return (x >> 24) | ((x >> 8) & 0x0000FF00) | ((x << 8) & 0x00FF0000) | (x << 24);
    }

    // mix functions for processBlock()
    inline uint32_t f1(uint32_t e, uint32_t f, uint32_t g) {
        uint32_t term1 = rotate(e, 6) ^ rotate(e, 11) ^ rotate(e, 25);
        uint32_t term2 = (e & f) ^ (~e & g);
        return term1 + term2;
    }

    inline uint32_t f2(uint32_t a, uint32_t b, uint32_t c) {
        uint32_t term1 = rotate(a, 2) ^ rotate(a, 13) ^ rotate(a, 22);
        uint32_t term2 = ((a | b) & c) | (a & b); 
        return term1 + term2;
    }
}


/// process 64 bytes
void SHA256::processBlock(const void* data) {
    // get last hash
    uint32_t a = m_hash[0];
    uint32_t b = m_hash[1];
    uint32_t c = m_hash[2];
    uint32_t d = m_hash[3];
    uint32_t e = m_hash[4];
    uint32_t f = m_hash[5];
    uint32_t g = m_hash[6];
    uint32_t h = m_hash[7];

    // data represented as 16x 32-bit words
    const uint32_t* input = (uint32_t*)data;
    // convert to big endian
    uint32_t words[64];
    int i;
    for (i = 0; i < 16; i++) {
        #if defined(__BYTE_ORDER) && (__BYTE_ORDER != 0) && (__BYTE_ORDER == __BIG_ENDIAN)
            words[i] = input[i];
        #else
            words[i] = swap(input[i]);
        #endif
    }

    uint32_t x, y; // temporaries

    // first round
    x = h + f1(e, f, g) + 0x428a2f98 + words[0]; y = f2(a, b, c); d += x; h = x + y;
    x = g + f1(d, e, f) + 0x71374491 + words[1]; y = f2(h, a, b); c += x; g = x + y;
    x = f + f1(c, d, e) + 0xb5c0fbcf + words[2]; y = f2(g, h, a); b += x; f = x + y;
    x = e + f1(b, c, d) + 0xe9b5dba5 + words[3]; y = f2(f, g, h); a += x; e = x + y;
    x = d + f1(a, b, c) + 0x3956c25b + words[4]; y = f2(e, f, g); h += x; d = x + y;
    x = c + f1(h, a, b) + 0x59f111f1 + words[5]; y = f2(d, e, f); g += x; c = x + y;
    x = b + f1(g, h, a) + 0x923f82a4 + words[6]; y = f2(c, d, e); f += x; b = x + y;
    x = a + f1(f, g, h) + 0xab1c5ed5 + words[7]; y = f2(b, c, d); e += x; a = x + y;

    // second round
    x = h + f1(e, f, g) + 0xd807aa98 + words[8]; y = f2(a, b, c); d += x; h = x + y;
    x = g + f1(d, e, f) + 0x12835b01 + words[9]; y = f2(h, a, b); c += x; g = x + y;
    x = f + f1(c, d, e) + 0x243185be + words[10]; y = f2(g, h, a); b += x; f = x + y;
    x = e + f1(b, c, d) + 0x550c7dc3 + words[11]; y = f2(f, g, h); a += x; e = x + y;
    x = d + f1(a, b, c) + 0x72be5d74 + words[12]; y = f2(e, f, g); h += x; d = x + y;
    x = c + f1(h, a, b) + 0x80deb1fe + words[13]; y = f2(d, e, f); g += x; c = x + y;
    x = b + f1(g, h, a) + 0x9bdc06a7 + words[14]; y = f2(c, d, e); f += x; b = x + y;
    x = a + f1(f, g, h) + 0xc19bf174 + words[15]; y = f2(b, c, d); e += x; a = x + y;

    // extend to 24 words
    for (; i < 24; i++) {
        words[i] = words[i - 16] +
            (rotate(words[i - 15], 7) ^ rotate(words[i - 15], 18) ^ (words[i - 15] >> 3)) +
            words[i - 7] +
            (rotate(words[i - 2], 17) ^ rotate(words[i - 2], 19) ^ (words[i - 2] >> 10));
    }
       
    // third round
    x = h + f1(e, f, g) + 0xe49b69c1 + words[16]; y = f2(a, b, c); d += x; h = x + y;
    x = g + f1(d, e, f) + 0xefbe4786 + words[17]; y = f2(h, a, b); c += x; g = x + y;
    x = f + f1(c, d, e) + 0x0fc19dc6 + words[18]; y = f2(g, h, a); b += x; f = x + y;
    x = e + f1(b, c, d) + 0x240ca1cc + words[19]; y = f2(f, g, h); a += x; e = x + y;
    x = d + f1(a, b, c) + 0x2de92c6f + words[20]; y = f2(e, f, g); h += x; d = x + y;
    x = c + f1(h, a, b) + 0x4a7484aa + words[21]; y = f2(d, e, f); g += x; c = x + y;
    x = b + f1(g, h, a) + 0x5cb0a9dc + words[22]; y = f2(c, d, e); f += x; b = x + y;
    x = a + f1(f, g, h) + 0x76f988da + words[23]; y = f2(b, c, d); e += x; a = x + y;

    // extend to 32 words
    for (; i < 32; i++) {
        words[i] = words[i - 16] +
            (rotate(words[i - 15], 7) ^ rotate(words[i - 15], 18) ^ (words[i - 15] >> 3)) +
            words[i - 7] +
            (rotate(words[i - 2], 17) ^ rotate(words[i - 2], 19) ^ (words[i - 2] >> 10));
    }
        
    // fourth round
    x = h + f1(e, f, g) + 0x983e5152 + words[24]; y = f2(a, b, c); d += x; h = x + y;
    x = g + f1(d, e, f) + 0xa831c66d + words[25]; y = f2(h, a, b); c += x; g = x + y;
    x = f + f1(c, d, e) + 0xb00327c8 + words[26]; y = f2(g, h, a); b += x; f = x + y;
    x = e + f1(b, c, d) + 0xbf597fc7 + words[27]; y = f2(f, g, h); a += x; e = x + y;
    x = d + f1(a, b, c) + 0xc6e00bf3 + words[28]; y = f2(e, f, g); h += x; d = x + y;
    x = c + f1(h, a, b) + 0xd5a79147 + words[29]; y = f2(d, e, f); g += x; c = x + y;
    x = b + f1(g, h, a) + 0x06ca6351 + words[30]; y = f2(c, d, e); f += x; b = x + y;
    x = a + f1(f, g, h) + 0x14292967 + words[31]; y = f2(b, c, d); e += x; a = x + y;

    // extend to 40 words
    for (; i < 40; i++) {
        words[i] = words[i - 16] +
            (rotate(words[i - 15], 7) ^ rotate(words[i - 15], 18) ^ (words[i - 15] >> 3)) +
            words[i - 7] +
            (rotate(words[i - 2], 17) ^ rotate(words[i - 2], 19) ^ (words[i - 2] >> 10));
    }
        
    // fifth round
    x = h + f1(e, f, g) + 0x27b70a85 + words[32]; y = f2(a, b, c); d += x; h = x + y;
    x = g + f1(d, e, f) + 0x2e1b2138 + words[33]; y = f2(h, a, b); c += x; g = x + y;
    x = f + f1(c, d, e) + 0x4d2c6dfc + words[34]; y = f2(g, h, a); b += x; f = x + y;
    x = e + f1(b, c, d) + 0x53380d13 + words[35]; y = f2(f, g, h); a += x; e = x + y;
    x = d + f1(a, b, c) + 0x650a7354 + words[36]; y = f2(e, f, g); h += x; d = x + y;
    x = c + f1(h, a, b) + 0x766a0abb + words[37]; y = f2(d, e, f); g += x; c = x + y;
    x = b + f1(g, h, a) + 0x81c2c92e + words[38]; y = f2(c, d, e); f += x; b = x + y;
    x = a + f1(f, g, h) + 0x92722c85 + words[39]; y = f2(b, c, d); e += x; a = x + y;

    // extend to 48 words
    for (; i < 48; i++) {
        words[i] = words[i - 16] +
            (rotate(words[i - 15], 7) ^ rotate(words[i - 15], 18) ^ (words[i - 15] >> 3)) +
            words[i - 7] +
            (rotate(words[i - 2], 17) ^ rotate(words[i - 2], 19) ^ (words[i - 2] >> 10));
    }
        
    // sixth round
    x = h + f1(e, f, g) + 0xa2bfe8a1 + words[40]; y = f2(a, b, c); d += x; h = x + y;
    x = g + f1(d, e, f) + 0xa81a664b + words[41]; y = f2(h, a, b); c += x; g = x + y;
    x = f + f1(c, d, e) + 0xc24b8b70 + words[42]; y = f2(g, h, a); b += x; f = x + y;
    x = e + f1(b, c, d) + 0xc76c51a3 + words[43]; y = f2(f, g, h); a += x; e = x + y;
    x = d + f1(a, b, c) + 0xd192e819 + words[44]; y = f2(e, f, g); h += x; d = x + y;
    x = c + f1(h, a, b) + 0xd6990624 + words[45]; y = f2(d, e, f); g += x; c = x + y;
    x = b + f1(g, h, a) + 0xf40e3585 + words[46]; y = f2(c, d, e); f += x; b = x + y;
    x = a + f1(f, g, h) + 0x106aa070 + words[47]; y = f2(b, c, d); e += x; a = x + y;

    // extend to 56 words
    for (; i < 56; i++) {
        words[i] = words[i - 16] +
            (rotate(words[i - 15], 7) ^ rotate(words[i - 15], 18) ^ (words[i - 15] >> 3)) +
            words[i - 7] +
            (rotate(words[i - 2], 17) ^ rotate(words[i - 2], 19) ^ (words[i - 2] >> 10));
    }
        
    // seventh round
    x = h + f1(e, f, g) + 0x19a4c116 + words[48]; y = f2(a, b, c); d += x; h = x + y;
    x = g + f1(d, e, f) + 0x1e376c08 + words[49]; y = f2(h, a, b); c += x; g = x + y;
    x = f + f1(c, d, e) + 0x2748774c + words[50]; y = f2(g, h, a); b += x; f = x + y;
    x = e + f1(b, c, d) + 0x34b0bcb5 + words[51]; y = f2(f, g, h); a += x; e = x + y;
    x = d + f1(a, b, c) + 0x391c0cb3 + words[52]; y = f2(e, f, g); h += x; d = x + y;
    x = c + f1(h, a, b) + 0x4ed8aa4a + words[53]; y = f2(d, e, f); g += x; c = x + y;
    x = b + f1(g, h, a) + 0x5b9cca4f + words[54]; y = f2(c, d, e); f += x; b = x + y;
    x = a + f1(f, g, h) + 0x682e6ff3 + words[55]; y = f2(b, c, d); e += x; a = x + y;

    // extend to 64 words
    for (; i < 64; i++) {
        words[i] = words[i - 16] +
            (rotate(words[i - 15], 7) ^ rotate(words[i - 15], 18) ^ (words[i - 15] >> 3)) +
            words[i - 7] +
            (rotate(words[i - 2], 17) ^ rotate(words[i - 2], 19) ^ (words[i - 2] >> 10));
    }
        
    // eight round
    x = h + f1(e, f, g) + 0x748f82ee + words[56]; y = f2(a, b, c); d += x; h = x + y;
    x = g + f1(d, e, f) + 0x78a5636f + words[57]; y = f2(h, a, b); c += x; g = x + y;
    x = f + f1(c, d, e) + 0x84c87814 + words[58]; y = f2(g, h, a); b += x; f = x + y;
    x = e + f1(b, c, d) + 0x8cc70208 + words[59]; y = f2(f, g, h); a += x; e = x + y;
    x = d + f1(a, b, c) + 0x90befffa + words[60]; y = f2(e, f, g); h += x; d = x + y;
    x = c + f1(h, a, b) + 0xa4506ceb + words[61]; y = f2(d, e, f); g += x; c = x + y;
    x = b + f1(g, h, a) + 0xbef9a3f7 + words[62]; y = f2(c, d, e); f += x; b = x + y;
    x = a + f1(f, g, h) + 0xc67178f2 + words[63]; y = f2(b, c, d); e += x; a = x + y;

    // update hash
    m_hash[0] += a;
    m_hash[1] += b;
    m_hash[2] += c;
    m_hash[3] += d;
    m_hash[4] += e;
    m_hash[5] += f;
    m_hash[6] += g;
    m_hash[7] += h;
}


/// add arbitrary number of bytes
void SHA256::add(const void* data, size_t numBytes) {
    const uint8_t* current = (const uint8_t*)data;

    if (m_bufferSize > 0) {
        while (numBytes > 0 && m_bufferSize < BlockSize) {
            m_buffer[m_bufferSize++] = *current++;
            numBytes--;
        }
    }

    // full buffer
    if (m_bufferSize == BlockSize) {
        processBlock(m_buffer);
        m_numBytes += BlockSize;
        m_bufferSize = 0;
    }

    // no more data ?
    if (numBytes == 0) {
        return;
    }
       
    // process full blocks
    while (numBytes >= BlockSize) {
        processBlock(current);
        current += BlockSize;
        m_numBytes += BlockSize;
        numBytes -= BlockSize;
    }

    // keep remaining bytes in buffer
    while (numBytes > 0) {
        this->m_buffer[m_bufferSize++] = *current++;
        numBytes--;
    }
}


/// process final block, less than 64 bytes
void SHA256::processBuffer() {
    // the input bytes are considered as bits strings, where the first bit is the most significant bit of the byte

    // - append "1" bit to message
    // - append "0" bits until message length in bit mod 512 is 448
    // - append length as 64 bit integer

    // number of bits
    size_t paddedLength = m_bufferSize * 8;

    // plus one bit set to 1 (always appended)
    paddedLength++;

    // number of bits must be (numBits % 512) = 448
    size_t lower11Bits = paddedLength & 511;

    if (lower11Bits <= 448) {
        paddedLength += 448 - lower11Bits;
    }
    else {
        paddedLength += 512 + 448 - lower11Bits;
    }

    // convert from bits to bytes
    paddedLength /= 8;

    // only needed if additional data flows over into a second block
    unsigned char extra[BlockSize];

    // append a "1" bit, 128 => binary 10000000
    if (m_bufferSize < BlockSize) {
        m_buffer[m_bufferSize] = 128;
    }
    else {
        extra[0] = 128;
    }
    
    size_t i;
    for (i = m_bufferSize + 1; i < BlockSize; i++) {
        m_buffer[i] = 0;
    }
        
    for (; i < paddedLength; i++) {
        extra[i - BlockSize] = 0;
    }
    
    // add message length in bits as 64 bit number
    uint64_t msgBits = 8 * (m_numBytes + m_bufferSize);

    // find right position
    unsigned char* addLength;

    if (paddedLength < BlockSize) {
        addLength = m_buffer + paddedLength;
    }
    else {
        addLength = extra + paddedLength - BlockSize;
    }
        
    // must be big endian
    *addLength++ = (unsigned char)((msgBits >> 56) & 0xFF);
    *addLength++ = (unsigned char)((msgBits >> 48) & 0xFF);
    *addLength++ = (unsigned char)((msgBits >> 40) & 0xFF);
    *addLength++ = (unsigned char)((msgBits >> 32) & 0xFF);
    *addLength++ = (unsigned char)((msgBits >> 24) & 0xFF);
    *addLength++ = (unsigned char)((msgBits >> 16) & 0xFF);
    *addLength++ = (unsigned char)((msgBits >> 8) & 0xFF);
    *addLength = (unsigned char)(msgBits & 0xFF);

    // process blocks
    processBlock(m_buffer);
    // flowed over into a second block ?
    if (paddedLength > BlockSize) {
        processBlock(extra);
    }
        
}

/// return latest hash as 64 hex characters
std::string SHA256::getHash() {
    // compute hash (as raw bytes)
    unsigned char rawHash[HashBytes];
    getHash(rawHash);

    // convert to hex string
    std::string result;
    result.reserve(2 * HashBytes);
    for (int i = 0; i < HashBytes; i++) {
        static const char dec2hex[17] = "0123456789abcdef";
        result += dec2hex[(rawHash[i] >> 4) & 15];
        result += dec2hex[rawHash[i] & 15];
    }

    return result;
}

/// return latest hash as bytes
void SHA256::getHash(unsigned char buffer[SHA256::HashBytes]) {
    // save old hash if buffer is partially filled
    uint32_t oldHash[HashValues];
    for (int i = 0; i < HashValues; i++) {
        oldHash[i] = m_hash[i];
    }
        
    // process remaining bytes
    processBuffer();

    unsigned char* current = buffer;
    for (int i = 0; i < HashValues; i++) {
        *current++ = (m_hash[i] >> 24) & 0xFF;
        *current++ = (m_hash[i] >> 16) & 0xFF;
        *current++ = (m_hash[i] >> 8) & 0xFF;
        *current++ = m_hash[i] & 0xFF;

        // restore old hash
        m_hash[i] = oldHash[i];
    }
}

#endif // _SHA_256

#ifndef _SHA_384
#define _SHA_384

class SHA384 {
private:

    const uint64 hPrime[8] = { 0xcbbb9d5dc1059ed8ULL,
                                0x629a292a367cd507ULL,
                                0x9159015a3070dd17ULL,
                                0x152fecd8f70e5939ULL,
                                0x67332667ffc00b31ULL,
                                0x8eb44a8768581511ULL,
                                0xdb0c2e0d64f98fa7ULL,
                                0x47b5481dbefa4fa4ULL
    };

    const uint64 k[80] = { 0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL,
              0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
              0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL, 0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
              0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
              0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL, 0x983e5152ee66dfabULL,
              0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
              0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL,
              0x53380d139d95b3dfULL, 0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
              0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
              0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL, 0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
              0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL,
              0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
              0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL, 0xca273eceea26619cULL,
              0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
              0x113f9804bef90daeULL, 0x1b710b35131c471bULL, 0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
              0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL };

    uint64** preprocess(const unsigned char* input, size_t& nBuffer);
    void appendLen(size_t l, uint64& lo, uint64& hi);
    void process(uint64** buffer, size_t nBuffer, uint64* h);
    std::string digest(uint64* h);
    void freeBuffer(uint64** buffer, size_t nBuffer);

    // Operations

// Constants
    unsigned int const SEQUENCE_LEN = (1024 / 64);
    size_t const HASH_LEN = 8;
    size_t const WORKING_VAR_LEN = 8;
    size_t const MESSAGE_SCHEDULE_LEN = 80;
    size_t const MESSAGE_BLOCK_SIZE = 1024;
    size_t const CHAR_LEN_BITS = 8;
    size_t const OUTPUT_LEN = 6;
    size_t const WORD_LEN = 8;

public:
    std::string hash(const std::string input);

    SHA384();
    ~SHA384();
};



SHA384::SHA384() {
}

SHA384::~SHA384() {
}

/**
 * Returns a string digest using the SHA384 algorithm
 * @param input message string used as an input to the SHA384 algorithm, must be < size_t bits
 */
std::string SHA384::hash(const std::string input) {
    size_t nBuffer; // amount of message blocks
    uint64** buffer; // message block buffers (each 1024-bit = 16 64-bit words)
    uint64* h = new uint64[HASH_LEN]; // buffer holding the message digest (512-bit = 8 64-bit words)

    buffer = preprocess((unsigned char*)input.c_str(), nBuffer);
    process(buffer, nBuffer, h);

    freeBuffer(buffer, nBuffer);
    return digest(h);
}

/**
 * Preprocessing of the SHA384 algorithm
 * @param input message in byte representation
 * @param nBuffer amount of message blocks
 */
uint64** SHA384::preprocess(const unsigned char* input, size_t& nBuffer) {
    // Padding: input || 1 || 0*k || l (in 128-bit representation)
    size_t mLen = strlen((const char*)input);
    size_t l = mLen * CHAR_LEN_BITS; // length of input in bits
    size_t k = (896 - 1 - l) % MESSAGE_BLOCK_SIZE; // length of zero bit padding (l + 1 + k = 896 mod 1024) 
    nBuffer = (l + 1 + k + 128) / MESSAGE_BLOCK_SIZE;

    uint64** buffer = new uint64 * [nBuffer];

    for (size_t i = 0; i < nBuffer; i++) {
        buffer[i] = new uint64[SEQUENCE_LEN];
    }

    uint64 in;
    size_t index;

    // Either copy existing message, add 1 bit or add 0 bit
    for (size_t i = 0; i < nBuffer; i++) {
        for (size_t j = 0; j < SEQUENCE_LEN; j++) {
            in = 0x0ULL;
            for (size_t k = 0; k < WORD_LEN; k++) {
                index = i * 128 + j * 8 + k;
                if (index < mLen) {
                    in = in << 8 | (uint64)input[index];
                }
                else if (index == mLen) {
                    in = in << 8 | 0x80ULL;
                }
                else {
                    in = in << 8 | 0x0ULL;
                }
            }
            buffer[i][j] = in;
        }
    }

    // Append the length to the last two 64-bit blocks
    appendLen(l, buffer[nBuffer - 1][SEQUENCE_LEN - 1], buffer[nBuffer - 1][SEQUENCE_LEN - 2]);
    return buffer;
}

/**
 * Processing of the SHA384 algorithm
 * @param buffer array holding the preprocessed
 * @param nBuffer amount of message blocks
 * @param h array of output message digest
 */
void SHA384::process(uint64** buffer, size_t nBuffer, uint64* h) {
    uint64 s[8];
    uint64 w[80];

    memcpy(h, hPrime, WORKING_VAR_LEN * sizeof(uint64));

    for (size_t i = 0; i < nBuffer; i++) {
        // copy over to message schedule
        memcpy(w, buffer[i], SEQUENCE_LEN * sizeof(uint64));

        // Prepare the message schedule
        for (size_t j = 16; j < MESSAGE_SCHEDULE_LEN; j++) {
            w[j] = w[j - 16] + sig0(w[j - 15]) + w[j - 7] + sig1(w[j - 2]);
        }
        // Initialize the working variables
        memcpy(s, h, WORKING_VAR_LEN * sizeof(uint64));

        // Compression
        for (size_t j = 0; j < MESSAGE_SCHEDULE_LEN; j++) {
            uint64 temp1 = s[7] + Sig1(s[4]) + Ch(s[4], s[5], s[6]) + k[j] + w[j];
            uint64 temp2 = Sig0(s[0]) + Maj(s[0], s[1], s[2]);

            s[7] = s[6];
            s[6] = s[5];
            s[5] = s[4];
            s[4] = s[3] + temp1;
            s[3] = s[2];
            s[2] = s[1];
            s[1] = s[0];
            s[0] = temp1 + temp2;
        }

        // Compute the intermediate hash values
        for (size_t j = 0; j < WORKING_VAR_LEN; j++) {
            h[j] += s[j];
        }
    }

}

/**
 * Appends the length of the message in the last two message blocks
 * @param l message size in bits
 * @param lo pointer to second last message block
 * @param hi pointer to last message block
 */
void SHA384::appendLen(size_t l, uint64& lo, uint64& hi) {
    lo = l;
    hi = 0x00ULL;
}

/**
 * Outputs the final message digest in hex representation
 * @param h array of output message digest
 */
std::string SHA384::digest(uint64* h) {
    std::stringstream ss;
    for (size_t i = 0; i < OUTPUT_LEN; i++) {
        ss << std::hex << std::setw(16) << std::setfill('0') << h[i];
    }
    delete[] h;
    return ss.str();
}

/**
 * Free the buffer correctly
 * @param buffer array holding the preprocessed
 * @param nBuffer amount of message blocks
 */
void SHA384::freeBuffer(uint64** buffer, size_t nBuffer) {
    for (size_t i = 0; i < nBuffer; i++) {
        delete[] buffer[i];
    }

    delete[] buffer;
}

#endif // 

#ifndef _SHA_512
#define _SHA_512

class SHA512 {
private:

    const uint64 hPrime[8] = { 0x6a09e667f3bcc908ULL,
                                0xbb67ae8584caa73bULL,
                                0x3c6ef372fe94f82bULL,
                                0xa54ff53a5f1d36f1ULL,
                                0x510e527fade682d1ULL,
                                0x9b05688c2b3e6c1fULL,
                                0x1f83d9abfb41bd6bULL,
                                0x5be0cd19137e2179ULL
    };

    const uint64 k[80] = { 0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL,
              0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL, 0x12835b0145706fbeULL,
              0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL, 0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
              0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
              0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL, 0x983e5152ee66dfabULL,
              0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
              0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL,
              0x53380d139d95b3dfULL, 0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
              0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
              0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL, 0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL,
              0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL,
              0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
              0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL, 0xca273eceea26619cULL,
              0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL,
              0x113f9804bef90daeULL, 0x1b710b35131c471bULL, 0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
              0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL };

    uint64** preprocess(const unsigned char* input, size_t& nBuffer);
    void appendLen(size_t l, uint64& lo, uint64& hi);
    void process(uint64** buffer, size_t nBuffer, uint64* h);
    std::string digest(uint64* h);
    void freeBuffer(uint64** buffer, size_t nBuffer);

    // Operations

// Constants
    unsigned int const SEQUENCE_LEN = (1024 / 64);
    size_t const HASH_LEN = 8;
    size_t const WORKING_VAR_LEN = 8;
    size_t const MESSAGE_SCHEDULE_LEN = 80;
    size_t const MESSAGE_BLOCK_SIZE = 1024;
    size_t const CHAR_LEN_BITS = 8;
    size_t const OUTPUT_LEN = 8;
    size_t const WORD_LEN = 8;

public:
    std::string hash(const std::string input);

    SHA512();
    ~SHA512();
};


//constructor

SHA512::SHA512() {
}


//destructor

SHA512::~SHA512() {
}

/**
 * Returns a message digest using the SHA512 algorithm
 * @param input message string used as an input to the SHA512 algorithm, must be < size_t bits
 */
std::string SHA512::hash(const std::string input) {
    size_t nBuffer; // amount of message blocks
    uint64** buffer; // message block buffers (each 1024-bit = 16 64-bit words)
    uint64* h = new uint64[HASH_LEN]; // buffer holding the message digest (512-bit = 8 64-bit words)

    buffer = preprocess((unsigned char*)input.c_str(), nBuffer);
    process(buffer, nBuffer, h);

    freeBuffer(buffer, nBuffer);
    return digest(h);
}

/**
 * Preprocessing of the SHA512 algorithm
 * @param input message in byte representation
 * @param nBuffer amount of message blocks
 */
uint64** SHA512::preprocess(const unsigned char* input, size_t& nBuffer) {
    // Padding: input || 1 || 0*k || l (in 128-bit representation)
    size_t mLen = strlen((const char*)input);
    size_t l = mLen * CHAR_LEN_BITS; // length of input in bits
    size_t k = (896 - 1 - l) % MESSAGE_BLOCK_SIZE; // length of zero bit padding (l + 1 + k = 896 mod 1024) 
    nBuffer = (l + 1 + k + 128) / MESSAGE_BLOCK_SIZE;

    uint64** buffer = new uint64 * [nBuffer];

    for (size_t i = 0; i < nBuffer; i++) {
        buffer[i] = new uint64[SEQUENCE_LEN];
    }

    uint64 in;
    size_t index;

    // Either copy existing message, add 1 bit or add 0 bit
    for (size_t i = 0; i < nBuffer; i++) {
        for (size_t j = 0; j < SEQUENCE_LEN; j++) {
            in = 0x0ULL;
            for (size_t k = 0; k < WORD_LEN; k++) {
                index = i * 128 + j * 8 + k;
                if (index < mLen) {
                    in = in << 8 | (uint64)input[index];
                }
                else if (index == mLen) {
                    in = in << 8 | 0x80ULL;
                }
                else {
                    in = in << 8 | 0x0ULL;
                }
            }
            buffer[i][j] = in;
        }
    }

    // Append the length to the last two 64-bit blocks
    appendLen(l, buffer[nBuffer - 1][SEQUENCE_LEN - 1], buffer[nBuffer - 1][SEQUENCE_LEN - 2]);
    return buffer;
}

/**
 * Processing of the SHA512 algorithm
 * @param buffer array holding the preprocessed
 * @param nBuffer amount of message blocks
 * @param h array of output message digest
 */
void SHA512::process(uint64** buffer, size_t nBuffer, uint64* h) {
    uint64 s[8];
    uint64 w[80];

    memcpy(h, hPrime, WORKING_VAR_LEN * sizeof(uint64));

    for (size_t i = 0; i < nBuffer; i++) {
        // copy over to message schedule
        memcpy(w, buffer[i], SEQUENCE_LEN * sizeof(uint64));

        // Prepare the message schedule
        for (size_t j = 16; j < MESSAGE_SCHEDULE_LEN; j++) {
            w[j] = w[j - 16] + sig0(w[j - 15]) + w[j - 7] + sig1(w[j - 2]);
        }
        // Initialize the working variables
        memcpy(s, h, WORKING_VAR_LEN * sizeof(uint64));

        // Compression
        for (size_t j = 0; j < MESSAGE_SCHEDULE_LEN; j++) {
            uint64 temp1 = s[7] + Sig1(s[4]) + Ch(s[4], s[5], s[6]) + k[j] + w[j];
            uint64 temp2 = Sig0(s[0]) + Maj(s[0], s[1], s[2]);

            s[7] = s[6];
            s[6] = s[5];
            s[5] = s[4];
            s[4] = s[3] + temp1;
            s[3] = s[2];
            s[2] = s[1];
            s[1] = s[0];
            s[0] = temp1 + temp2;
        }

        // Compute the intermediate hash values
        for (size_t j = 0; j < WORKING_VAR_LEN; j++) {
            h[j] += s[j];
        }
    }

}

/**
 * Appends the length of the message in the last two message blocks
 * @param l message size in bits
 * @param lo pointer to second last message block
 * @param hi pointer to last message block
 */
void SHA512::appendLen(size_t l, uint64& lo, uint64& hi) {
    lo = l;
    hi = 0x00ULL;
}

/**
 * Outputs the final message digest in hex representation
 * @param h array of output message digest
 */
std::string SHA512::digest(uint64* h) {
    std::stringstream ss;
    for (size_t i = 0; i < OUTPUT_LEN; i++) {
        ss << std::hex << std::setw(16) << std::setfill('0') << h[i];
    }
    delete[] h;
    return ss.str();
}

/**
 * Free the buffer correctly
 * @param buffer array holding the preprocessed
 * @param nBuffer amount of message blocks
 */
void SHA512::freeBuffer(uint64** buffer, size_t nBuffer) {
    for (size_t i = 0; i < nBuffer; i++) {
        delete[] buffer[i];
    }

    delete[] buffer;
}

#endif // _SHA_512
