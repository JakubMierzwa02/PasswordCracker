/**
 * @file HashAlgorithms.h
*/

#ifndef HASHALGORITHMS_H
#define HASHALGORITHMS_H

#include <string>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>

/**
 * @class HashAlgorithms
 * @brief Provides static methods for hashing strings using various algorithms
*/

class HashAlgorithms
{
public:
    /**
     * @brief Hashes an input string using SHA-256 and returns the hexadecimal representation of the hash
     * @param input The input string to be hashed
     * @return A string containing the hexadecimal representation of the SHA-256 hash of the input
    */
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