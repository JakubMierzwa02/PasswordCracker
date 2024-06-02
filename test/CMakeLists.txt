cmake_minimum_required(VERSION 3.10)

set(This PasswordCrackerTest)

add_subdirectory(googletest)

include_directories(${PROJECT_SOURCE_DIR}/src)

add_executable(${This}
    password_cracker_test.cpp
    ../src/PasswordCracker.cpp
    ../src/HashAlgorithms.h
)

target_link_libraries(${This}
    gtest
    gtest_main
    gmock_main
    pthread
    cryptopp
)

enable_testing()

add_test(
    NAME ${This}
    COMMAND ${This}
)