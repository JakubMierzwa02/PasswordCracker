#include <iostream>
#include <cctype>
#include "PasswordCracker.h"

int main()
{
    std::string targetHash = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

    for (int i = 0; i < targetHash.size(); i++)
    {
        targetHash[i] = std::toupper(targetHash[i]);
    }

    int numThreads;
    std::cout << "Enter number of threads: ";
    std::cin >> numThreads;

    PasswordCracker cracker(targetHash);
    cracker.startCracking(numThreads);

    return 0;
}