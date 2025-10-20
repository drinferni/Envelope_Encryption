#include "IntegrityMonitor.h"
#include <filesystem>
#include <iostream>

namespace fs = std::filesystem;

IntegrityMonitor::IntegrityMonitor(const std::string& vault_path) : vault_path_(vault_path) {}

void IntegrityMonitor::zeroize_all_keys() {
    std::cout << "TAMPER EVENT DETECTED! Zeroizing all keys..." << std::endl;
    for (const auto& entry : fs::directory_iterator(vault_path_)) {
        fs::remove(entry.path());
    }
    std::cout << "Vault has been zeroized." << std::endl;
}