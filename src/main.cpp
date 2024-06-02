#include <iostream>
#include <cctype>
#include "PasswordCracker.h"

int main()
{
    std::string hashFile;

    std::cout << "Enter the file path containing the hashes: ";
    std::cin >> hashFile;

    int numThreads;
    std::cout << "Enter number of threads: ";
    std::cin >> numThreads;

    PasswordCracker cracker;

    cracker.startCracking(hashFile, numThreads);

    return 0;
}