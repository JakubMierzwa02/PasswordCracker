#include "PasswordCracker.h"

#ifdef _WIN32
#include <conio.h>
#define SLEEP_MS(ms) Sleep(ms)

#else
#include <termios.h>
#include <unistd.h>
#define SLEEP_MS(ms) usleep((ms) * 1000)
void setNonBlockingInput(bool enable)
{
    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);
    if (enable)
        tty.c_lflag &= ~(ICANON | ECHO);
    else
        tty.c_lflag |= (ICANON | ECHO);
    (void) tcsetattr(STDIN_FILENO, TCSANOW, &tty);
}
#endif

void userInterface(PasswordCracker& cracker, std::atomic<bool>& stopFlag)
{
    setNonBlockingInput(true);
    while (!stopFlag.load())
    {
        std::cout << "Enter 'q' to interrupt the process\n";
        char input;
        bool inputAvailable = false;

#ifdef _WIN32
        if (_khbit())
        {
            input = _getch();
            inputAvailable = true;
        }
#else
        if (read(STDIN_FILENO, &input, 1) > 0)
        {
            inputAvailable = true;
        }
#endif

        if (inputAvailable)
        {
            if (input == 'q')
            {
                cracker.interrupt();
                stopFlag.store(true);
                break;
            }
        }
        SLEEP_MS(10);
    }
    setNonBlockingInput(false);
}

int main()
{
    std::string hashFile;

    std::cout << "Enter the file path containing the hashes: ";
    std::cin >> hashFile;

    int numThreads;
    std::cout << "Enter number of threads: ";
    std::cin >> numThreads;

    PasswordCracker cracker;

    std::atomic<bool> stopFlag(false);

    std::thread uiThread(userInterface, std::ref(cracker), std::ref(stopFlag));
    cracker.startCracking(hashFile, numThreads);
    stopFlag.store(true);
    uiThread.join();

    return 0;
}