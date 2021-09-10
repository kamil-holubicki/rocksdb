#include "env/env_encryption_ctr_aes.h"
#include "env/master_key_manager.h"
#include "rocksdb/stream_cipher.h"
#include "rocksdb/system_clock.h"
#include "util/random.h"
#include <openssl/evp.h>

namespace ROCKSDB_NAMESPACE {

/******************************************************************************/
CTRAesCipherStream::CTRAesCipherStream(const char* file_key, const char* iv)
{
    m_encryptor = Aes_ctr::get_encryptor();
    m_encryptor->open((const unsigned char*)file_key, (const unsigned char*)iv);

    m_decryptor = Aes_ctr::get_decryptor();
    m_decryptor->open((const unsigned char*)file_key, (const unsigned char*)iv);
}

CTRAesCipherStream::~CTRAesCipherStream()
{
    m_encryptor->close();
    m_decryptor->close();
}

size_t CTRAesCipherStream::BlockSize()
{
//    assert(0);
    return 0;
}

Status CTRAesCipherStream::Encrypt(uint64_t fileOffset, char* data, size_t dataSize)
{
  // todo: add offset tracking to avoid underlaying cipher reinitialization if not needed
  m_encryptor->set_stream_offset(fileOffset);
  m_encryptor->encrypt((unsigned char*)data, (const unsigned char*)data, dataSize);
  return Status::OK();
}

Status CTRAesCipherStream::Decrypt(uint64_t fileOffset, char* data, size_t dataSize)
{
  // todo: add offset tracking to avoid underlaying cipher reinitialization if not needed
  m_decryptor->set_stream_offset(fileOffset);
  m_decryptor->decrypt((unsigned char*)data, (const unsigned char*)data, dataSize);
  return Status::OK();
}

void CTRAesCipherStream::AllocateScratch(std::string&)
{

}

Status CTRAesCipherStream::EncryptBlock(uint64_t blockIndex, char* data, char* scratch)
{
//    assert(0);
    return Status::OK();
}

Status CTRAesCipherStream::DecryptBlock(uint64_t blockIndex, char* data, char* scratch)
{
//    assert(0);
    return Status::OK();
}

/******************************************************************************/
static constexpr char kKeyMagic[]       = "rdbe001";

static constexpr int KEY_MAGIC_SIZE     = strlen(kKeyMagic);
static constexpr int MASTER_KEY_ID_SIZE = sizeof(uint32_t);
static constexpr int S_UUID_SIZE        = 36;
static constexpr int CRC_SIZE           = sizeof(uint32_t);
static constexpr int FILE_KEY_SIZE      = 32;
static constexpr int IV_SIZE            = 16;

static constexpr int KEY_MAGIC_OFFSET     = 0;
static constexpr int MASTER_KEY_ID_OFFSET = KEY_MAGIC_OFFSET + KEY_MAGIC_SIZE;
static constexpr int S_UUID_OFFSET        = MASTER_KEY_ID_OFFSET + MASTER_KEY_ID_SIZE;
static constexpr int CRC_OFFSET           = S_UUID_OFFSET + S_UUID_SIZE;
static constexpr int FILE_KEY_OFFSET      = CRC_OFFSET + CRC_SIZE;
static constexpr int IV_OFFSET            = FILE_KEY_OFFSET + FILE_KEY_SIZE;


/******************************************************************************/
const char* CTRAesEncryptionProvider::kCTRAesProviderName = "CTRAES";


CTRAesEncryptionProvider::CTRAesEncryptionProvider()
: masterKeyManager_(new MasterKeyManager())
{
}

CTRAesEncryptionProvider::~CTRAesEncryptionProvider() {

}

CTRAesEncryptionProvider::CTRAesEncryptionProvider(std::shared_ptr<MasterKeyManager> mmm)
: masterKeyManager_(mmm)
{

}

Status CTRAesEncryptionProvider::Feed(Slice& prefix)
{
    // here we get the whole prefix of the encrypted file
    uint32_t masterKeyId = 0;
    memcpy(&masterKeyId, prefix.data()+MASTER_KEY_ID_OFFSET, MASTER_KEY_ID_SIZE);

    std::string serverUuid(prefix.data()+S_UUID_OFFSET, S_UUID_SIZE);

    masterKeyManager_->RegisterMasterKeyId(masterKeyId, serverUuid);

    return Status::OK();
}


const char* CTRAesEncryptionProvider::Name() const
{
  return kCTRAesProviderName;
}

size_t CTRAesEncryptionProvider::GetPrefixLength() const
{
  return defaultPrefixLength;
}

/*
Encryption prefix:
 4 bytes		KEY_MAGIC_V1 (e001) 		not encrypted
 4 bytes		master_key_id			not encrypted
36 bytes		s_uuid				not encrypted
 4 bytes		CRC (unencrypted key + iv)	not encrypted
32 bytes		key				encrypted
16 bytes		iv				encrypted
*/
Status CTRAesEncryptionProvider::CreateNewPrefix(const std::string& fname, char* prefix,
                       size_t prefixLength) const
{
  memcpy((void*)(&prefix[KEY_MAGIC_OFFSET]), kKeyMagic, KEY_MAGIC_SIZE);

  std::string masterKey;
  uint32_t masterKeyId = 0;

  masterKeyManager_->GetMostRecentMasterKey(&masterKey, &masterKeyId);
  // todo: do something like mach_write_to_4
  // store the master key id
  memcpy((void*)(&prefix[MASTER_KEY_ID_OFFSET]), &masterKeyId, MASTER_KEY_ID_SIZE);

  // store server uuid
  std::string serverUuid;
  masterKeyManager_->GetServerUuid(&serverUuid);
  memcpy((void*)(&prefix[S_UUID_OFFSET]), serverUuid.data(), S_UUID_SIZE);

  // Create & seed rnd.
  // todo: maybe openssl would be better for random numbers?
  Random rnd((uint32_t)SystemClock::Default()->NowMicros());
  // Fill the not clear-text part of the prefix with random values.
  // file key and IV are generated here as well
  for (size_t i = FILE_KEY_OFFSET; i < prefixLength; i++) {
    prefix[i] = rnd.Uniform(256) & 0xFF;
  }

#if 0
  memset((void*)(&prefix[FILE_KEY_OFFSET]), 'K', FILE_KEY_SIZE);
  memset((void*)(&prefix[IV_OFFSET]), 'V', IV_SIZE);
#endif

  // calculate and store CRC of not encrypted file key and IV
  // todo: skip calculation for now
  uint32_t crc = 0xABCDABCD;
  memcpy((void*)(&prefix[CRC_OFFSET]), &crc, CRC_SIZE);

  // encrypt file key and IV with master key
  unsigned char iv[IV_SIZE] = {0};
  auto encryptor = Aes_ctr::get_encryptor();
  encryptor->open((const unsigned char*)masterKey.data(), iv);
  unsigned char* dataToEncrypt = (unsigned char*)(&prefix[FILE_KEY_OFFSET]);
  encryptor->encrypt(dataToEncrypt, dataToEncrypt, FILE_KEY_SIZE + IV_SIZE);


#if 0
  memset((void*)(&prefix[MASTER_KEY_ID_OFFSET]), 'M', MASTER_KEY_ID_SIZE);
  memset((void*)(&prefix[S_UUID_OFFSET]), 'U', S_UUID_SIZE);
  memset((void*)(&prefix[FILE_KEY_OFFSET]), 'K', FILE_KEY_SIZE);
  memset((void*)(&prefix[IV_OFFSET]), 'V', IV_SIZE);
  memset((void*)(&prefix[CRC_OFFSET]), 'C', CRC_SIZE);
#endif
  return Status::OK();
}

// prefix is encrypted, reencrypt with new master key if needed.
Status CTRAesEncryptionProvider::ReencryptPrefix(Slice& prefix) const {
    // todo: introduce GetMostRecentMasterKeyId, to avoid getting it over and
    // over from keyring component
    std::string newestMasterKey;
    uint32_t newestMasterKeyId;
    masterKeyManager_->GetMostRecentMasterKey(&newestMasterKey, &newestMasterKeyId);

    uint32_t fileMasterKeyId;
    memcpy(&fileMasterKeyId, prefix.data()+MASTER_KEY_ID_OFFSET, MASTER_KEY_ID_SIZE);

    if(newestMasterKeyId == fileMasterKeyId){
        return Status::OK();
    }

    // decrypt the header using old MK
    std::string suuid(prefix.data()+S_UUID_OFFSET, S_UUID_SIZE);
    std::string fileMasterKey;

    masterKeyManager_->GetMasterKey(fileMasterKeyId, suuid, &fileMasterKey);
    unsigned char iv[IV_SIZE] = {0};
    auto decryptor = Aes_ctr::get_decryptor();
    decryptor->open((const unsigned char*)fileMasterKey.data(), iv);

    auto data = (unsigned char*)(prefix.data()+FILE_KEY_OFFSET);
    decryptor->decrypt(data, data, FILE_KEY_SIZE + IV_SIZE);

    // encrypt using the new master key
    auto encryptor = Aes_ctr::get_encryptor();
    encryptor->open((const unsigned char*)newestMasterKey.data(), iv);

    encryptor->encrypt(data, data, FILE_KEY_SIZE + IV_SIZE);

    // update CRC
    // todo: skip calculation for now
    uint32_t crc = 0xABCDABCD;
    memcpy((void*)(prefix.data()+CRC_OFFSET), &crc, CRC_SIZE);

    // update MK id
    memcpy((void*)(prefix.data()+MASTER_KEY_ID_OFFSET), &newestMasterKeyId, MASTER_KEY_ID_SIZE);

    return Status::OK();
}

Status CTRAesEncryptionProvider::CreateCipherStream(
      const std::string& fname, const EnvOptions& options, Slice& prefix,
      std::unique_ptr<BlockAccessCipherStream>* result)
{
  if( 0 != memcmp(prefix.data(), kKeyMagic, KEY_MAGIC_SIZE)) {
      fprintf(stderr, "KH: not encrypted file detected\n");
 //     assert(0);
     return Status::OK();
  }

  Slice masterKeyIdSlice(prefix.data() + MASTER_KEY_ID_OFFSET, MASTER_KEY_ID_SIZE);
  Slice suuidSlice(prefix.data() + S_UUID_OFFSET, S_UUID_SIZE);
  uint32_t masterKeyId = 0;
  memcpy(&masterKeyId, masterKeyIdSlice.data(), masterKeyIdSlice.size());
  std::string suuid(suuidSlice.data(), suuidSlice.size());

  std::string masterKey;
  masterKeyManager_->GetMasterKey(masterKeyId, suuid, &masterKey);

  // Decrypt key and iv with master key (AES ECB)

  unsigned char iv[IV_SIZE] = {0};
  auto decryptor = Aes_ctr::get_decryptor();
  decryptor->open((const unsigned char*)masterKey.data(), iv);

  unsigned char dataToDecrypt[FILE_KEY_SIZE + IV_SIZE];
  memcpy(dataToDecrypt, prefix.data()+FILE_KEY_OFFSET, FILE_KEY_SIZE+IV_SIZE);

  decryptor->decrypt(dataToDecrypt, dataToDecrypt, FILE_KEY_SIZE + IV_SIZE);

  // TODO: Calculate and validate CRC
  uint32_t crc = 0;
  memcpy(&crc, prefix.data()+CRC_OFFSET, CRC_SIZE);
  if(crc != 0xABCDABCD) {
      fprintf(stderr, "WRONG CRC!\n");
  }

  Slice fileKey((char*)dataToDecrypt, FILE_KEY_SIZE);
  Slice fileIV((char*)(dataToDecrypt+FILE_KEY_SIZE), IV_SIZE);

  // Create cipher stream
  return CreateCipherStreamFromPrefix(fileKey, fileIV, result);
}

Status CTRAesEncryptionProvider::AddCipher(const std::string& /*descriptor*/, const char* /*cipher*/,
                 size_t /*len*/, bool /*for_write*/)
{
  return Status::OK();
}

Status CTRAesEncryptionProvider::TEST_Initialize()
{
  // todo
  return Status::OK();
}

Status CTRAesEncryptionProvider::CreateCipherStreamFromPrefix(
      const Slice& key, const Slice& iv,
      std::unique_ptr<BlockAccessCipherStream>* result)
{
  (*result) = std::unique_ptr<BlockAccessCipherStream>(
      new CTRAesCipherStream(key.data(), iv.data()));
  return Status::OK();
}

std::string CTRAesEncryptionProvider::GetMarker() const {
    return kKeyMagic;
}
}  // namespace