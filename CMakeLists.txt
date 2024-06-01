cmake_minimum_required(VERSION 3.10)

set(This PasswordCracker)
project(${This})

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_executable(PasswordCracker
    src/main.cpp
    src/PasswordCracker.cpp
    src/HashAlgorithms.h
)

target_link_libraries(PasswordCracker cryptopp)
