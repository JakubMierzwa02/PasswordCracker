/**
 * @file PasswordCracker.cpp
 */

#include "PasswordCracker.h"

/**
 * @brief Constructor for the PasswordCracker class
 */
PasswordCracker::PasswordCracker()
    : cracked(false), interrupted(false)
{
}

/**
 * @brief Starts the password cracking process using the specified hash file and number of threads
 * @param hashFile The file containing the hash to be cracked
 * @param numThreads The number of threads to use for the cracking process
 */
void PasswordCracker::startCracking(const std::string &hashFile, int numThreads)
{
    std::ifstream file(hashFile);
    if (!file)
    {
        std::cerr << "Could not open the hash file" << std::endl;
        return;
    }

    std::string hash;
    while (file >> hash)
    {
        targetHash = hash;

        for (int i = 0; i < targetHash.size(); i++)
        {
            targetHash[i] = std::toupper(targetHash[i]);
        }

        cracked = false;
        interrupted = false;
        crackedPassword.clear();

        auto start = std::chrono::high_resolution_clock::now();

        dictionaryAttack("../common_passwords.txt", numThreads);

        std::vector<std::thread> threads;
        for (int i = 0; i < numThreads; ++i)
        {
            threads.emplace_back(&PasswordCracker::bruteForce, this, i, numThreads);
        }
        for (auto &thread : threads)
        {
            thread.join();
        }

        auto end = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> duration = end - start;

        if (cracked)
        {
            std::cout << "Password cracked: " << crackedPassword << std::endl;
        }
        else
        {
            std::cout << "Password not found" << std::endl;
        }

        std::cout << "Time taken: " << duration.count() << " seconds" << std::endl;

        logResults("../results.txt");

        if (interrupted)
        {
            std::cout << "Process interrupted by user." << std::endl;
            break;
        }
    }
    file.close();
}

/**
 * @brief Performs a dictionary attack using the specified dictionary file and number of threads
 * @param dictionaryFile The file containing a list of potential passwords
 * @param numThreads The number of threads to use for the dictionary attack
 */
void PasswordCracker::dictionaryAttack(const std::string &dictionaryFile, int numThreads)
{
    std::ifstream file(dictionaryFile);
    if (!file)
    {
        std::cerr << "Could not open the dictionary file." << std::endl;
        return;
    }

    std::vector<std::string> passwords;
    std::string password;
    while (file >> password)
    {
        passwords.push_back(password);
    }
    file.close();

    std::vector<std::thread> threads;
    for (int i = 0; i < numThreads; ++i)
    {
        threads.emplace_back(&PasswordCracker::dictionaryWorker, this, i, numThreads, passwords);
    }

    for (auto &thread : threads)
    {
        thread.join();
    }
}

/**
 * @brief Checks if the given password matches the target hash
 * @param password The password to be checked
 * @return True if the password matches the hash, false otherwise
 */
bool PasswordCracker::checkPassword(const std::string &password)
{
    std::string hashedPassword = HashAlgorithms::hashSHA256(password);
    return compareHash(hashedPassword);
}

/**
 * @brief Checks if the password has been successfully cracked
 * @return True if the password is cracked, false otherwise
 */
bool PasswordCracker::isCracked() const
{
    return cracked.load();
}

/**
 * @brief Logs the results of the password cracking attempt to a file
 * @param filename The name of the file to log the results to
 */
void PasswordCracker::logResults(const std::string &filename) const
{
    std::ofstream file(filename, std::ios::app);
    if (file.is_open())
    {
        file << "Target hash: " << targetHash << std::endl;
        if (cracked)
        {
            file << "Password cracked: " << crackedPassword << std::endl;
        }
        else
        {
            file << "Password not found\n";
        }
        file << '\n';
    }
    file.close();
}

/**
 * @brief Interrupts the password cracking process
 */
void PasswordCracker::interrupt()
{
    interrupted.store(true);
}

/**
 * @brief Performs a brute force attack to crack the password
 * @param threadID The ID of the current thread
 * @param numThreads The total number of threads
 */
void PasswordCracker::bruteForce(int threadID, int numThreads)
{
    int maxLength = 10;
    for (int length = 1; length <= maxLength && !cracked.load() && !interrupted.load(); ++length)
    {
        int totalCombinations = pow(73, length);
        for (int i = threadID; i < totalCombinations && !cracked.load() && !interrupted.load(); i += numThreads)
        {
            std::string attempt = generatePassword(length, i);
            std::string hashedAttempt = HashAlgorithms::hashSHA256(attempt);
            if (checkPassword(attempt))
            {
                crackedPassword = attempt;
                cracked.store(true);
                break;
            }
        }
    }
}

/**
 * @brief Worker function for the dictionary attack
 * @param threadID The ID of the current thread
 * @param numThreads The total number of threads
 * @param passwords The list of potential passwords
 */
void PasswordCracker::dictionaryWorker(int threadID, int numThreads, const std::vector<std::string> &passwords)
{
    for (size_t i = threadID; i < passwords.size() && !cracked.load() && !interrupted.load(); i += numThreads)
    {
        if (checkPassword(passwords[i]))
        {
            crackedPassword = passwords[i];
            cracked.store(true);
            break;
        }
    }
}

/**
 * @brief Compares the given hash with the target hash
 * @param hash The hash to be compared
 * @return True if the hashes match, false otherwise
 */
bool PasswordCracker::compareHash(const std::string &hash)
{
    return hash == targetHash;
}

/**
 * @brief Generates a password of the given length and index
 * @param length The length of the password to be generated
 * @param index The index used to generate the password
 * @return The generated password
 */
std::string PasswordCracker::generatePassword(int length, int index)
{
    const std::string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()";

    std::string password(length, ' ');
    for (int i = 0; i < length; ++i)
    {
        password[length - 1 - i] = charset[index % charset.size()];
        index /= charset.size();
    }
    return password;
}