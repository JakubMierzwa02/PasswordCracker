/**
 * @file PasswordCracker.h
*/
#ifndef PASSWORDCRACKER_H
#define PASSWORDCRACKER_H

#include <string>
#include <vector>
#include <atomic>
#include <thread>
#include <iostream>
#include <chrono>
#include <fstream>
#include "../test/googletest/googletest/include/gtest/gtest_prod.h"
#include "HashAlgorithms.h"

/**
 * @class PasswordCracker
 * @brief Implements methods to crack passwords using dictionary and brute-force attacks
*/
class PasswordCracker
{
public:
    /**
     * @brief Constructor for the PasswordCracker class
    */
    PasswordCracker();

    /**
     * @brief Logs the results of the password cracking attempt to a file
     * @param filename The name of the file to log the results to
    */
    void logResults(const std::string& filename) const;

    /**
     * @brief Starts the password cracking process using the specified hash file and number of threads
     * @param hashFile The file containing the hash to be cracked
     * @param numThreads The number of threads to use for the cracking process
    */
    void startCracking(const std::string& hashFile, int numThreads);

    /**
     * @brief Performs a dictionary attack using the specified dictionary file and number of threads
     * @param dictionaryFile The file containing a list of potential passwords
     * @param numThreads The number of threads to use for the dictionary attack
    */
    void dictionaryAttack(const std::string& dictionaryFile, int numThreads);
    bool checkPassword(const std::string& password);
    bool isCracked() const;
    void interrupt();

private:
    std::string targetHash;
    std::atomic<bool> cracked;
    std::atomic<bool> interrupted;
    std::string crackedPassword;

    void bruteForce(int threadID, int numThreads);
    void dictionaryWorker(int threadID, int numThreads, const std::vector<std::string>& passwords);
    bool compareHash(const std::string& hash);
    std::string generatePassword(int length, int index);

    FRIEND_TEST(PasswordCrackerTest, GeneratePassword);
    FRIEND_TEST(PasswordCrackerTest, CompareHash);
    FRIEND_TEST(PasswordCrackerTest, CheckPassword);
};

#endif