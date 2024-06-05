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
#include <unordered_set>
#include <mutex>
#include <condition_variable>
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

    /**
     * @brief Checks if the given password matches the target hash
     * @param password The password to be checked
     * @return True if the password matches the hash, false otherwise
    */
    bool checkPassword(const std::string& password);

    /**
     * @brief Checks if the password has been successfully cracked
     * @return True if the password is cracked, false otherwise
    */
    bool isCracked() const;

    /**
     * @brief Interrupts the password cracking process
    */
    void interrupt();

private:
    std::string targetHash;         ///< The hash that needs to be cracked
    std::atomic<bool> cracked;      ///< Indicates if the password has been cracked
    std::atomic<bool> interrupted;  ///< Indicates if the cracking process has been interrupted
    std::string crackedPassword;    ///< The cracked password
    std::mutex resultMutex;

    /**
     * @brief Performs a brute force attack to crack the password
     * @param threadID The ID of the current thread
     * @param numThreads The total number of threads
    */
    void bruteForce(int threadID, int numThreads);

    /**
     * @brief Worker function for the dictionary attack
     * @param threadID The ID of the current thread
     * @param numThreads The total number of threads
     * @param passwords The list of potential passwords
    */
    void dictionaryWorker(int threadID, int numThreads, const std::vector<std::string>& passwords);

    /**
     * @brief Compares the given hash with the target hash
     * @param hash The hash to be compared
     * @return True if the hashes match, false otherwise
    */
    bool compareHash(const std::string& hash);

    /**
     * @brief Generates a password of the given length and index
     * @param length The length of the password to be generated
     * @param index The index used to generate the password
     * @return The generated password
    */
    std::string generatePassword(int length, int index);

    FRIEND_TEST(PasswordCrackerTest, GeneratePassword);
    FRIEND_TEST(PasswordCrackerTest, CompareHash);
    FRIEND_TEST(PasswordCrackerTest, CheckPassword);
};

#endif