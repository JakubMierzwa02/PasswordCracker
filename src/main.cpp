#include <iostream>
#include <cctype>
#include "PasswordCracker.h"

int main()
{
    std::string targetHash = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8";

    for (int i = 0; i < targetHash.size(); i++)
    {
        targetHash[i] = std::toupper(targetHash[i]);
    }

    int numThreads;
    std::cout << "Enter number of threads: ";
    std::cin >> numThreads;

    PasswordCracker cracker(targetHash);

    cracker.dictionaryAttack("../common_passwords.txt", numThreads);

    cracker.startCracking(numThreads);

    return 0;
}