#include "PasswordCracker.h"

PasswordCracker::PasswordCracker(const std::string& targetHash)
    : targetHash(targetHash), cracked(false)
{

}

void PasswordCracker::startCracking(int numThreads)
{
    auto start = std::chrono::high_resolution_clock::now();

    std::vector<std::thread> threads;
    for (int i = 0; i < numThreads; ++i)
    {
        threads.emplace_back(&PasswordCracker::bruteForce, this, i, numThreads);
    }

    for (auto& thread : threads)
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
}

bool PasswordCracker::checkPassword(const std::string& password)
{
    std::string hashedPassword = HashAlgorithms::hashSHA256(password);
    return compareHash(hashedPassword);
}

bool PasswordCracker::isCracked() const
{
    return cracked.load();
}

void PasswordCracker::bruteForce(int threadID, int numThreads)
{
    int maxLength = 10;
    for (int length = 1; length <= maxLength && !cracked.load(); ++length)
    {
        int totalCombinations = pow(26, length);
        for (int i = threadID; i < totalCombinations && !cracked.load(); i += numThreads)
        {
            std::string attempt = generatePassword(length, i);
            std::string hashedAttempt = HashAlgorithms::hashSHA256(attempt);
            if (checkPassword(attempt))
            {
                crackedPassword = attempt;
                cracked.store(true);
                break;
            }
            // std::cout << "Thread " << threadID << ": Attempting " << attempt << " -> " << hashedAttempt << std::endl;
        }
    }
}

bool PasswordCracker::compareHash(const std::string& hash)
{
    return hash == targetHash;
}

std::string PasswordCracker::generatePassword(int length, int index)
{
    const std::string charset = "abcdefghijklmnopqrstuvwxyz";
    std::string password(length, ' ');
    for (int i = 0; i < length; ++i)
    {
        password[length - 1 - i] = charset[index % 26];
        index /= 26;
    }
    return password;
}