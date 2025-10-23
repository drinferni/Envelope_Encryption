#include <iostream>
#include <string>
#include <filesystem> // For final cleanup
#include "KeyVault.h"
#include "BaseCryptoProcessor.h"

namespace fs = std::filesystem;

/**
 * @brief Helper function to print test results in a standard format.
 * @param testName The name of the test being run.
 * @param result The boolean result of the test (true = PASSED, false = FAILED).
 * @return The test result.
 */
bool check(const std::string& testName, bool result) {
    std::cout << "  [Test] " << testName << ": " 
              << (result ? "PASSED" : "FAILED") << std::endl;
    return result;
}

int main() {
    const std::string VAULT_PATH = "CryptoProcessorTestLocker";
    bool allTestsPassed = true;

    std::cout << "--- Initializing Crypto Processor Test ---" << std::endl;
    
    // 1. Setup Vault and Processor
    KeyVault vault(VAULT_PATH);
    BaseCryptoProcessor processor(vault);
    vault.zeroizeAllKeys(); // Start with a clean slate

    std::cout << "\n--- 1. Creating Test Keys ---" << std::endl;
    
    // Create parent keys
    if (!check("Create 'WrapParentAES'", vault.createKey("WrapParentAES", "AES"))) allTestsPassed = false;
    if (!check("Create 'WrapParentRSA'", vault.createKey("WrapParentRSA", "RSA"))) allTestsPassed = false;
    if (!check("Create 'WrapParentEC'", vault.createKey("WrapParentEC", "EC"))) allTestsPassed = false;
    
    // Create child keys to be wrapped
    if (!check("Create 'Child_for_KWP'", vault.createKey("Child_for_KWP", "AES"))) allTestsPassed = false;
    if (!check("Create 'Child_for_KW'", vault.createKey("Child_for_KW", "AES"))) allTestsPassed = false;
    if (!check("Create 'Child_for_RSA'", vault.createKey("Child_for_RSA", "AES"))) allTestsPassed = false;
    if (!check("Create 'Child_for_EC'", vault.createKey("Child_for_EC", "AES"))) allTestsPassed = false;

    // 2. Get Original Keys for Comparison
    std::cout << "\n--- 2. Storing Original Plaintext Keys ---" << std::endl;
    KeyData child_kwp_orig = vault.getKey("Child_for_KWP");
    KeyData child_kw_orig = vault.getKey("Child_for_KW");
    KeyData child_rsa_orig = vault.getKey("Child_for_RSA");
    KeyData child_ec_orig = vault.getKey("Child_for_EC");

    if (!check("Got original KWP key", !child_kwp_orig.privateKey.empty())) allTestsPassed = false;
    if (!check("Got original KW key", !child_kw_orig.privateKey.empty())) allTestsPassed = false;
    if (!check("Got original RSA key", !child_rsa_orig.privateKey.empty())) allTestsPassed = false;
    if (!check("Got original EC key", !child_ec_orig.privateKey.empty())) allTestsPassed = false;
    std::cout << "  Original KW Key (first 8): " << child_kw_orig.privateKey.substr(0, 8) << "..." << std::endl;

    // 3. Test Wrapping
    std::cout << "\n--- 3. Testing Key Wrapping (Encryption) ---" << std::endl;
    
    if (!check("Wrap (AES-KWP)", 
        processor.wrapKey("WrapParentAES", "Child_for_KWP", "AES-KWP"))) allTestsPassed = false;

    // Note: Our generated AES key is 32 bytes, which is a multiple of 8,
    // so it is valid for AES-KW (RFC 3394)
    if (!check("Wrap (AES-KW)",
        processor.wrapKey("WrapParentAES", "Child_for_KW", "AES-KW"))) allTestsPassed = false;

    if (!check("Wrap (RSA-OAEP)",
        processor.wrapKey("WrapParentRSA", "Child_for_RSA", "RSA-OAEP"))) allTestsPassed = false;
    
    if (!check("Wrap (ECDH+AES-KWP)",
        processor.wrapKey("WrapParentEC", "Child_for_EC", "ECDH+AES-KWP"))) allTestsPassed = false;

    // 4. Verify Wrapped Key on Disk
    std::cout << "\n--- 4. Verifying Wrapped Key on Disk ---" << std::endl;
    KeyData child_kw_wrapped = vault.getKey("Child_for_KW");
    if (!check("Wrapped key on disk is different from original", 
        child_kw_orig.privateKey != child_kw_wrapped.privateKey)) allTestsPassed = false;
    
    if (!check("Wrapped key parent is correctly set", 
        child_kw_wrapped.parentKey == "WrapParentAES")) allTestsPassed = false;

    std::cout << "  Wrapped KW Key (first 8): " << child_kw_wrapped.privateKey.substr(0, 8) << "..." << std::endl;

    // 5. Test Unwrapping
    std::cout << "\n--- 5. Testing Key Unwrapping (Decryption) ---" << std::endl;
    
    std::string unwrapped_kwp = processor.unwrapKey("WrapParentAES", "Child_for_KWP");
    std::string unwrapped_kw = processor.unwrapKey("WrapParentAES", "Child_for_KW");
    std::string unwrapped_rsa = processor.unwrapKey("WrapParentRSA", "Child_for_RSA");
    std::string unwrapped_ec = processor.unwrapKey("WrapParentEC", "Child_for_EC");

    if (!check("Unwrapped (AES-KWP) matches original", unwrapped_kwp == child_kwp_orig.privateKey)) allTestsPassed = false;
    if (!check("Unwrapped (AES-KW) matches original", unwrapped_kw == child_kw_orig.privateKey)) allTestsPassed = false;
    if (!check("Unwrapped (RSA-OAEP) matches original", unwrapped_rsa == child_rsa_orig.privateKey)) allTestsPassed = false;
    if (!check("Unwrapped (ECDH+AES-KWP) matches original", unwrapped_ec == child_ec_orig.privateKey)) allTestsPassed = false;
    std::cout << "  Unwrapped KW Key (first 8): " << unwrapped_kw.substr(0, 8) << "..." << std::endl;

    // 6. Test Failure Cases
    std::cout << "\n--- 6. Testing Failure Cases ---" << std::endl;
    
    if (!check("Wrap with non-existent parent",
        !processor.wrapKey("NonExistentKey", "Child_for_KWP", "AES-KWP"))) allTestsPassed = false;

    if (!check("Wrap non-existent child",
        !processor.wrapKey("WrapParentAES", "NonExistentKey", "AES-KWP"))) allTestsPassed = false;
    
    if (!check("Wrap with wrong parent type (RSA parent, AES algo)",
        !processor.wrapKey("WrapParentRSA", "Child_for_KWP", "AES-KWP"))) allTestsPassed = false;
        
    std::string unwrap_fail = processor.unwrapKey("WrapParentAES", "NonExistentKey");
    if (!check("Unwrap non-existent child", unwrap_fail.empty())) allTestsPassed = false;
    
    std::string unwrap_fail_wrong_parent = processor.unwrapKey("WrapParentRSA", "Child_for_KWP");
    if (!check("Unwrap with wrong parent (RSA key, AES-KWP log)", unwrap_fail_wrong_parent.empty())) allTestsPassed = false;


    // 7. Final Cleanup
    std::cout << "\n--- 7. Cleaning Up ---" << std::endl;
    vault.zeroizeAllKeys();
    fs::remove_all(VAULT_PATH);
    std::cout << "  Removed directory: " << VAULT_PATH << std::endl;

    // --- Final Summary ---
    std::cout << "\n--- Final Summary ---" << std::endl;
    if (allTestsPassed) {
        std::cout << "All Crypto Processor Tests PASSED." << std::endl;
    } else {
        std::cout << "One or more Crypto Processor Tests FAILED." << std::endl;
    }
    std::cout << "-----------------------" << std::endl;

    return allTestsPassed ? 0 : 1;
}
