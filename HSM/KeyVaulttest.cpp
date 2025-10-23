#include <iostream>
#include <string>
#include <filesystem> // For final cleanup
#include "KeyVault.h"

// Helper function to print test results
bool check(const std::string& testName, bool condition) {
    std::cout << "  [TEST] " << testName << "... " 
              << (condition ? "PASSED" : "FAILED") << std::endl;
    return condition;
}

int main() {
    const std::string VAULT_PATH = "TestKeyLocker";
    std::cout << "--- Starting Key Vault Test ---" << std::endl;
    std::cout << "Using vault path: " << VAULT_PATH << "\n" << std::endl;

    bool allTestsPassed = true;

    // --- 1. Initialization and Master Key ---
    std::cout << "--- 1. Initialization ---" << std::endl;
    KeyVault vault(VAULT_PATH);
    std::string masterKey1 = vault.getMasterKey();
    
    if (!check("Master Key 1 is not empty", !masterKey1.empty())) {
        allTestsPassed = false;
    }
    std::cout << "  Master Key 1 (first 8 chars): " << masterKey1.substr(0, 8) << "..." << std::endl;


    // --- 2. Create Keys ---
    std::cout << "\n--- 2. Creating Keys ---" << std::endl;
    if (!check("Create 'TestAES'", vault.createKey("TestAES", "AES"))) allTestsPassed = false;
    if (!check("Create 'TestRSA'", vault.createKey("TestRSA", "RSA"))) allTestsPassed = false;
    if (!check("Create 'TestEC'", vault.createKey("TestEC", "EC"))) allTestsPassed = false;
    if (!check("Create 'ChildAES' with parent 'TestAES'", vault.createKey("ChildAES", "AES", "TestAES"))) allTestsPassed = false;
    

    // --- 3. Get Keys and Compare Data ---
    std::cout << "\n--- 3. Getting Keys and Comparing ---" << std::endl;
    
    // Test AES Key
    KeyData aesData = vault.getKey("TestAES");
    std::cout << "  Testing 'TestAES' data..." << std::endl;
    if (!check("  - Name matches", aesData.keyName == "TestAES")) allTestsPassed = false;
    if (!check("  - Algorithm matches", aesData.algorithm == "AES")) allTestsPassed = false;
    if (!check("  - Private key is not empty", !aesData.privateKey.empty())) allTestsPassed = false;
    if (!check("  - Public key is empty", aesData.publicKey.empty())) allTestsPassed = false;
    if (!check("  - Parent key is empty", aesData.parentKey.empty())) allTestsPassed = false;

    // Test RSA Key
    KeyData rsaData = vault.getKey("TestRSA");
    std::cout << "  Testing 'TestRSA' data..." << std::endl;
    if (!check("  - Name matches", rsaData.keyName == "TestRSA")) allTestsPassed = false;
    if (!check("  - Algorithm matches", rsaData.algorithm == "RSA")) allTestsPassed = false;
    if (!check("  - Private key is not empty", !rsaData.privateKey.empty())) allTestsPassed = false;
    if (!check("  - Public key is not empty", !rsaData.publicKey.empty())) allTestsPassed = false;

    // Test EC Key
    KeyData ecData = vault.getKey("TestEC");
    std::cout << "  Testing 'TestEC' data..." << std::endl;
    if (!check("  - Name matches", ecData.keyName == "TestEC")) allTestsPassed = false;
    if (!check("  - Algorithm matches", ecData.algorithm == "EC")) allTestsPassed = false;
    if (!check("  - Private key is not empty", !ecData.privateKey.empty())) allTestsPassed = false;
    if (!check("  - Public key is not empty", !ecData.publicKey.empty())) allTestsPassed = false;

    // Test Child Key
    KeyData childData = vault.getKey("ChildAES");
    std::cout << "  Testing 'ChildAES' data..." << std::endl;
    if (!check("  - Name matches", childData.keyName == "ChildAES")) allTestsPassed = false;
    if (!check("  - Algorithm matches", childData.algorithm == "AES")) allTestsPassed = false;
    if (!check("  - Parent key matches 'TestAES'", childData.parentKey == "TestAES")) allTestsPassed = false;


    // --- 4. Test Failure Cases ---
    std::cout << "\n--- 4. Testing Failure Cases ---" << std::endl;
    
    // Test Duplicate Creation
    bool duplicateSuccess = vault.createKey("TestAES", "AES");
    if (!check("Duplicate key creation fails", duplicateSuccess == false)) allTestsPassed = false;

    // Test Getting Non-existent Key
    KeyData badData = vault.getKey("NonExistentKey");
    if (!check("Get non-existent key returns empty struct", badData.algorithm.empty())) allTestsPassed = false;

    
    // --- 5. Zeroize and Verify ---
    std::cout << "\n--- 5. Zeroizing Vault ---" << std::endl;
    vault.zeroizeAllKeys();

    // Test Master Key Regeneration
    std::string masterKey2 = vault.getMasterKey();
    std::cout << "  Master Key 2 (first 8 chars): " << masterKey2.substr(0, 8) << "..." << std::endl;
    if (!check("Master Key 2 is not empty", !masterKey2.empty())) allTestsPassed = false;
    if (!check("Master Key 2 is different from Master Key 1", masterKey1 != masterKey2)) allTestsPassed = false;

    // Test that keys are gone
    KeyData postZeroizeData = vault.getKey("TestAES");
    if (!check("Key 'TestAES' is gone after zeroize", postZeroizeData.algorithm.empty())) allTestsPassed = false;


    // --- 6. Final Summary ---
    std::cout << "\n--- Test Summary ---" << std::endl;
    if (allTestsPassed) {
        std::cout << "RESULT: All tests PASSED!" << std::endl;
    } else {
        std::cout << "RESULT: One or more tests FAILED!" << std::endl;
    }
    std::cout << "----------------------" << std::endl;

    // Final cleanup
    std::cout << "Cleaning up test directory..." << std::endl;
    try {
        std::filesystem::remove_all(VAULT_PATH);
    } catch (const std::filesystem::filesystem_error& e) {
        std::cerr << "Cleanup failed: " << e.what() << std::endl;
    }

    return allTestsPassed ? 0 : 1; // Return 0 on success, 1 on failure
}

