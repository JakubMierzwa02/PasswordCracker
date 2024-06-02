#ifndef PASSWORDCRACKER_H
#define PASSWORDCRACKER_H

#include <string>
#include <vector>
#include <atomic>
#include <thread>
#include <iostream>
#include <chrono>
#include <fstream>

#include "HashAlgorithms.h"

class PasswordCracker
{
public:
    PasswordCracker();
    void logResults(const std::string& filename) const;
    void startCracking(const std::string& hashFile, int numThreads);
    void dictionaryAttack(const std::string& dictionaryFile, int numThreads);
    bool checkPassword(const std::string& password);
    bool isCracked() const;
    void interrupt();
    //bool shouldInterrupt() const;

private:
    std::string targetHash;
    std::atomic<bool> cracked;
    std::atomic<bool> interrupted;
    std::string crackedPassword;

    void bruteForce(int threadID, int numThreads);
    void dictionaryWorker(int threadID, int numThreads, const std::vector<std::string>& passwords);
    bool compareHash(const std::string& hash);
    std::string generatePassword(int length, int index);
};

#endif