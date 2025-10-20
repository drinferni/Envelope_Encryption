#ifndef KEY_LIFECYCLE_MANAGER_H
#define KEY_LIFECYCLE_MANAGER_H

#include "KeyVault.h"
#include <string>

class KeyLifecycleManager {
public:
    KeyLifecycleManager(KeyVault& vault);
    
    // Creates a new key
    bool create_key(const std::string& key_id, const std::string& algorithm);

    // Rotates a key (creates a new version)
    bool rotate_key(const std::string& key_id);

    // Disables a key
    bool disable_key(const std::string& key_id);

private:
    KeyVault& vault_;
};

#endif // KEY_LIFECYCLE_MANAGER_H