// src/AccessController.cpp
#include "AccessController.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <vector>

AccessController::AccessController(const std::string& policy_file) {
    std::ifstream file(policy_file);
    if (!file.is_open()) {
        // You might want to log an error here. For now, we'll proceed with empty policies.
        return;
    }

    std::string line;
    // Read the file line by line
    while (std::getline(file, line)) {
        std::stringstream ss(line);
        std::string item;
        std::vector<std::string> items;

        // Split the line by commas
        while (std::getline(ss, item, ',')) {
            // Trim whitespace (optional but good practice)
            item.erase(item.find_last_not_of(" \n\r\t")+1);
            item.erase(0, item.find_first_not_of(" \n\r\t"));
            if (!item.empty()) {
                items.push_back(item);
            }
        }

        if (items.size() >= 1) {
            // The first item is the principal
            std::string principal = items[0];
            // The rest are the allowed actions
            policies_[principal] = std::vector<std::string>(items.begin() + 1, items.end());
        }
    }
}

// The can_perform method remains unchanged.
bool AccessController::can_perform(const std::string& principal, const std::string& action) const {
    auto it = policies_.find(principal);
    if (it == policies_.end()) {
        return false; // Principal not found
    }
    const auto& allowed_actions = it->second;
    return std::find(allowed_actions.begin(), allowed_actions.end(), action) != allowed_actions.end();
}