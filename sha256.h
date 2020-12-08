#ifndef __SHA__256__H
#define __SHA__256__H

#include <cstdint>
#include <array>
#include <bit>

class SHA256
{
public:
    static constexpr unsigned int Sha256BlockSize = 32;

    constexpr SHA256()
        : data{},
          dataLen{0},
          bitlen{0},
          state {
              0x6a09e667,
              0xbb67ae85,
              0x3c6ef372,
              0xa54ff53a,
              0x510e527f,
              0x9b05688c,
              0x1f83d9ab,
              0x5be0cd19
          }
    {}

    constexpr std::array<std::uint8_t, Sha256BlockSize> hash(const uint8_t* data, size_t size)
    {
        update(data, size);
        return finalize();
    }

private:

    constexpr void sha256_transform(const std::array<uint8_t, 64>& data)
    {
        uint32_t a{}, b{}, c{}, d{}, e{}, f{}, g{}, h{}, i{}, j{}, t1{}, t2{}, m[64]{};

        for (i = 0, j = 0; i < 16; ++i, j += 4)
            m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
        for ( ; i < 64; ++i)
            m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

        a = state[0];
        b = state[1];
        c = state[2];
        d = state[3];
        e = state[4];
        f = state[5];
        g = state[6];
        h = state[7];

        for (i = 0; i < 64; ++i) {
            t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
            t2 = EP0(a) + MAJ(a,b,c);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
        state[5] += f;
        state[6] += g;
        state[7] += h;
    }

    constexpr void update(const uint8_t* data, std::size_t len)
    {
        for (uint32_t i = 0; i < len; ++i) {
            this->data[dataLen] = data[i];
            dataLen++;
            if (dataLen == 64) {
                sha256_transform(this->data);
                bitlen += 512;
                dataLen = 0;
            }
        }
    }

    constexpr std::array<uint8_t, Sha256BlockSize> finalize()
    {
        std::array<uint8_t, Sha256BlockSize> hash{};
        uint32_t i = dataLen;

        // Pad whatever data is left in the buffer.
        if (dataLen < 56) {
            this->data[i++] = 0x80;
            while (i < 56)
                this->data[i++] = 0x00;
        }
        else {
            this->data[i++] = 0x80;
            while (i < 64)
                this->data[i++] = 0x00;
            sha256_transform(this->data);
            std::fill_n(this->data.begin(), 56, 0);
        }

        // Append to the padding the total message's length in bits and transform.
        this->bitlen +=  this->dataLen * 8;
        this->data[63] = this->bitlen;
        this->data[62] = this->bitlen >> 8;
        this->data[61] = this->bitlen >> 16;
        this->data[60] = this->bitlen >> 24;
        this->data[59] = this->bitlen >> 32;
        this->data[58] = this->bitlen >> 40;
        this->data[57] = this->bitlen >> 48;
        this->data[56] = this->bitlen >> 56;
        sha256_transform(this->data);

        // Since this implementation uses little endian byte ordering and SHA uses big endian,
        // reverse all the bytes when copying the final state to the output hash.
        for (i = 0; i < 4; ++i) {
            hash[i]      = (state[0] >> (24 - i * 8)) & 0x000000ff;
            hash[i + 4]  = (state[1] >> (24 - i * 8)) & 0x000000ff;
            hash[i + 8]  = (state[2] >> (24 - i * 8)) & 0x000000ff;
            hash[i + 12] = (state[3] >> (24 - i * 8)) & 0x000000ff;
            hash[i + 16] = (state[4] >> (24 - i * 8)) & 0x000000ff;
            hash[i + 20] = (state[5] >> (24 - i * 8)) & 0x000000ff;
            hash[i + 24] = (state[6] >> (24 - i * 8)) & 0x000000ff;
            hash[i + 28] = (state[7] >> (24 - i * 8)) & 0x000000ff;
        }
        return hash;
    }

private:
    static uint32_t constexpr CH(uint32_t x, uint32_t y, uint32_t z)
    {
        return (x & y) ^ ((~x) & z);
    }
    static uint32_t constexpr MAJ(uint32_t x, uint32_t y, uint32_t z)
    {
        return (x & y) ^ (x & z) ^ (y & z);
    }
    static uint32_t constexpr EP0(uint32_t x)
    {
        return std::rotr(x, 2) ^ std::rotr(x, 13) ^ std::rotr(x, 22);
    }
    static uint32_t constexpr EP1(uint32_t x)
    {
        return std::rotr(x, 6) ^ std::rotr(x, 11) ^ std::rotr(x, 25);
    }
    static uint32_t constexpr SIG0(uint32_t x)
    {
        return std::rotr(x, 7) ^ std::rotr(x, 18) ^ (x >> 3);
    }
    static uint32_t constexpr SIG1(uint32_t x)
    {
        return std::rotr(x, 17) ^ std::rotr(x, 19) ^ (x >> 10);
    }

private:
    std::array<uint8_t, 64> data;
    uint32_t dataLen;
    std::size_t bitlen;
    std::array<uint32_t, 8> state;


    static constexpr std::array<uint32_t, 64> k = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };
};

#endif
