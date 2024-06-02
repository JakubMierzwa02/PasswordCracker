#include "PasswordCracker.h"

PasswordCracker::PasswordCracker()
    : cracked(false)
{

}

void PasswordCracker::startCracking(const std::string& hashFile, int numThreads)
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
        crackedPassword.clear();

        auto start = std::chrono::high_resolution_clock::now();

        dictionaryAttack("../common_passwords.txt", numThreads);

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

        logResults("../results.txt");
    }
}

void PasswordCracker::dictionaryAttack(const std::string& dictionaryFile, int numThreads)
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

    for (auto& thread : threads)
    {
        thread.join();
    }
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

void PasswordCracker::logResults(const std::string& filename) const
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

void PasswordCracker::bruteForce(int threadID, int numThreads)
{
    int maxLength = 10;
    for (int length = 1; length <= maxLength && !cracked.load(); ++length)
    {
        int totalCombinations = pow(73, length);
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
        }
    }
}

void PasswordCracker::dictionaryWorker(int threadID, int numThreads, const std::vector<std::string>& passwords)
{
    for (size_t i = threadID; i < passwords.size() && !cracked.load(); i += numThreads)
    {
        if (checkPassword(passwords[i]))
        {
            crackedPassword = passwords[i];
            cracked.store(true);
            break;
        }
    }
}

bool PasswordCracker::compareHash(const std::string& hash)
{
    return hash == targetHash;
}

std::string PasswordCracker::generatePassword(int length, int index)
{
    const std::string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()";

    std::string password(length, ' ');
    for (int i = 0; i < length; ++i)
    {
        password[length - 1 - i] = charset[index % 73];
        index /= 73;
    }
    return password;
}