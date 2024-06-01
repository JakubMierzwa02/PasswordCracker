#ifndef HASHALGORITHMS_H
#define HASHALGORITHMS_H

#include <string>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>

class HashAlgorithms
{
public:
    static std::string hashSHA256(const std::string& input)
    {
        CryptoPP::SHA256 hash;
        std::string digest;

        CryptoPP::StringSource s(input, true, 
            new CryptoPP::HashFilter(hash, 
            new CryptoPP::HexEncoder(
            new CryptoPP::StringSink(digest))));

        return digest;
    }
};

#endif