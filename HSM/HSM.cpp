// src/main.cpp
#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>

#include "AccessController.h"
#include "KeyVault.h"
#include "KeyLifecycleManager.h"
#include "EnvelopeEncryptionManager.h"

void print_usage() {
    std::cerr << "Usage: ./hsm <command> [options]\n"
              << "Commands:\n"
              << "  create_key   --key_id <id> --user <principal>\n"
              << "  encrypt      --key_id <id> --user <principal> --data <plaintext>\n"
              << "  decrypt      --user <principal> --bundle <json_bundle>\n"
              << "  rotate_key   --key_id <id> --user <principal>\n"
              << "Example:\n"
              << "  ./hsm create_key --key_id my-first-key --user admin\n"
              << "  ./hsm encrypt --key_id my-first-key --user app_user --data 'hello world'\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage();
        return 1;
    }

    // --- Configuration ---
    const char* master_pass_env = std::getenv("HSM_MASTER_PASSWORD");
    if (!master_pass_env) {
        std::cerr << "Error: HSM_MASTER_PASSWORD environment variable not set." << std::endl;
        return 1;
    }
    std::string master_password(master_pass_env);
    std::string vault_path = "./vault";
    std::string policy_file = "./policies.json";

    // --- Initialize HSM Modules ---
    AccessController access_controller(policy_file);
    KeyVault key_vault(vault_path, master_password);
    KeyLifecycleManager lifecycle_manager(key_vault);
    EnvelopeEncryptionManager envelope_manager(key_vault);

    // --- Command Parsing & Dispatch ---
    std::string command = argv[1];
    std::map<std::string, std::string> args;
    for (int i = 2; i < argc; i += 2) {
        if (i + 1 < argc) {
            args[argv[i]] = argv[i + 1];
        }
    }

    if (args.find("--user") == args.end()) {
        std::cerr << "Error: --user argument is required." << std::endl;
        return 1;
    }
    std::string user = args["--user"];

    try {
        if (command == "create_key") {
            if (!access_controller.can_perform(user, "CREATE_KEY")) {
                throw std::runtime_error("Access Denied");
            }
            if (lifecycle_manager.create_key(args.at("--key_id"), "AES-256-GCM")) {
                std::cout << "Key '" << args.at("--key_id") << "' created successfully." << std::endl;
            } else {
                std::cerr << "Error: Failed to create key." << std::endl;
            }
        } else if (command == "encrypt") {
             if (!access_controller.can_perform(user, "ENCRYPT")) {
                throw std::runtime_error("Access Denied");
            }
            std::string plaintext_str = args.at("--data");
            std::vector<unsigned char> plaintext(plaintext_str.begin(), plaintext_str.end());
            std::string bundle;
            if (envelope_manager.encrypt(args.at("--key_id"), plaintext, bundle)) {
                std::cout << "Encryption successful. Bundle:\n" << bundle << std::endl;
            } else {
                 std::cerr << "Error: Encryption failed." << std::endl;
            }
        } else if (command == "decrypt") {
            if (!access_controller.can_perform(user, "DECRYPT")) {
                throw std::runtime_error("Access Denied");
            }
            std::vector<unsigned char> plaintext;
            if (envelope_manager.decrypt(args.at("--bundle"), plaintext)) {
                std::cout << "Decryption successful. Plaintext:\n" << std::string(plaintext.begin(), plaintext.end()) << std::endl;
            } else {
                std::cerr << "Error: Decryption failed." << std::endl;
            }
        } else if (command == "rotate_key") {
            if (!access_controller.can_perform(user, "ROTATE_KEY")) {
                throw std::runtime_error("Access Denied");
            }
             if (lifecycle_manager.rotate_key(args.at("--key_id"))) {
                std::cout << "Key '" << args.at("--key_id") << "' rotated successfully." << std::endl;
            } else {
                std::cerr << "Error: Failed to rotate key." << std::endl;
            }
        } else {
            print_usage();
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}