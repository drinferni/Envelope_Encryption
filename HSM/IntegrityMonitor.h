#ifndef INTEGRITY_MONITOR_H
#define INTEGRITY_MONITOR_H

#include <string>

class IntegrityMonitor {
public:
    IntegrityMonitor(const std::string& vault_path);
    // Simulates a tamper event by deleting all keys
    void zeroize_all_keys();

private:
    std::string vault_path_;
};

#endif // INTEGRITY_MONITOR_H