#include <gtest/gtest.h>
#include "../src/HashAlgorithms.h"
#include "../src/PasswordCracker.h"

class PasswordCracker;

TEST(HashAlgorithmsTest, HashSHA256)
{
    std::string password = "abc";
    std::string expected_hash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    for (int i = 0; i < expected_hash.size(); ++i)
        expected_hash[i] = std::toupper(expected_hash[i]);
    EXPECT_EQ(HashAlgorithms::hashSHA256(password), expected_hash);
}

class PasswordCrackerTest : public ::testing::Test
{
protected:
    PasswordCracker cracker;
};

TEST_F(PasswordCrackerTest, GeneratePassword)
{
    std::string password = cracker.generatePassword(3, 0);
    EXPECT_EQ(password, "aaa");

    password = cracker.generatePassword(3, 1);
    EXPECT_EQ(password, "aab");

    password = cracker.generatePassword(3, 70);
    EXPECT_NE(password, "aba");

    password = cracker.generatePassword(3, 703);
    EXPECT_NE(password, "aaa");
}

TEST_F(PasswordCrackerTest, CompareHash)
{
    cracker.targetHash = HashAlgorithms::hashSHA256("password");
    EXPECT_TRUE(cracker.compareHash(HashAlgorithms::hashSHA256("password")));
    EXPECT_FALSE(cracker.compareHash(HashAlgorithms::hashSHA256("wrongpassword")));
}

TEST_F(PasswordCrackerTest, CheckPassword)
{
    cracker.targetHash = HashAlgorithms::hashSHA256("password");
    EXPECT_TRUE(cracker.checkPassword("password"));
    EXPECT_FALSE(cracker.checkPassword("wrongpassword"));
}

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}