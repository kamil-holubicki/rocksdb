#pragma once

#include <string>
#include <rocksdb/rocksdb_namespace.h>


namespace ROCKSDB_NAMESPACE {

class MasterKeyManager {
    public:
        MasterKeyManager();
        ~MasterKeyManager();

        int GetMostRecentMasterKey(std::string *masterKey, uint32_t *masterKeyId);
        int GetMasterKey(uint32_t masterKeyId, const std::string &suuid, std::string *masterKey);
        int GetServerUuid(std::string *serverUuid);
};


}  // namespace