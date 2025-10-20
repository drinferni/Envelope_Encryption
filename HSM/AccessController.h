#ifndef ACCESS_CONTROLLER_H
#define ACCESS_CONTROLLER_H

#include <string>
#include <vector>
#include <map>

using json = nlohmann::json;

class AccessController {
public:
    AccessController(const std::string& policy_file);
    bool can_perform(const std::string& principal, const std::string& action) const;

private:
    std::map<std::string, std::vector<std::string>> policies_;
};

#endif // ACCESS_CONTROLLER_H