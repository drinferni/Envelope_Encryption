#include "AccessController.h"
#include <fstream>
#include <algorithm>

AccessController::AccessController(const std::string& policy_file) {
    std::ifstream ifs(policy_file);
    if (ifs.is_open()) {
        json j;
        ifs >> j;
        policies_ = j.get<std::map<std::string, std::vector<std::string>>>();
    }
}

bool AccessController::can_perform(const std::string& principal, const std::string& action) const {
    auto it = policies_.find(principal);
    if (it == policies_.end()) {
        return false; // Principal not found
    }
    const auto& allowed_actions = it->second;
    return std::find(allowed_actions.begin(), allowed_actions.end(), action) != allowed_actions.end();
}