#ifndef PASSWORDCRACKER_H
#define PASSWORDCRACKER_H

#include <string>
#include <vector>
#include <atomic>
#include <thread>
#include <iostream>

#include "HashAlgorithms.h"

class PasswordCracker
{
public:
    PasswordCracker(const std::string& targetHash);
    void startCracking(int numThreads);
    bool checkPassword(const std::string& password);
    bool isCracked() const;

private:
    std::string targetHash;
    std::atomic<bool> cracked;
    std::string crackedPassword;
    void bruteForce(int threadID, int numThreads);
    bool compareHash(const std::string& hash);
    std::string generatePassword(int length, int index);
};

#endif