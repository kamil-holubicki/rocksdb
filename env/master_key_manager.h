#pragma once

#include <string>
#include <rocksdb/rocksdb_namespace.h>


namespace ROCKSDB_NAMESPACE {

class MasterKeyManager {
    public:
        MasterKeyManager();
        virtual ~MasterKeyManager();

        virtual int GetMostRecentMasterKey(std::string *masterKey, uint32_t *masterKeyId);
        virtual int GetMasterKey(uint32_t masterKeyId, const std::string &suuid, std::string *masterKey);
        virtual int GetServerUuid(std::string *serverUuid);

        virtual void RegisterMasterKeyId(uint32_t masterKeyId);
};


}  // namespace