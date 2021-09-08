#include "env/env_encryption_ctr_aes.h"
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

const char* CTRAesEncryptionProvider::kCTRAesProviderName = "CTRAES";
const char* CTRAesEncryptionProvider::kKeyMagic = "e001";

const char* CTRAesEncryptionProvider::Name() const
{
  return kCTRAesProviderName;
}

size_t CTRAesEncryptionProvider::GetPrefixLength() const
{
  return defaultPrefixLength;
}

/*
Encryption header:
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
  memcpy(prefix, kKeyMagic, KEY_MAGIC_SIZE);
  // todo: master_key_id
  // todo: server uuid
  // skip crc for now

  // Create & seed rnd.
  // todo: maybe openssl would be better for random numbers?
  Random rnd((uint32_t)SystemClock::Default()->NowMicros());
  // Fill the not clear-text part of the prefix with random values.
  size_t fileKeyStart = KEY_MAGIC_SIZE + MASTER_KEY_ID_SIZE + S_UUID_SIZE + CRC_SIZE;
  for (size_t i = fileKeyStart; i < prefixLength; i++) {
    prefix[i] = rnd.Uniform(256) & 0xFF;
  }
#if 1
  memset((void*)(&prefix[KEY_MAGIC_SIZE]), 'M', MASTER_KEY_ID_SIZE);
  memset((void*)(&prefix[KEY_MAGIC_SIZE + MASTER_KEY_ID_SIZE]), 'U', S_UUID_SIZE);
  memset((void*)(&prefix[fileKeyStart]), 'K', FILE_KEY_SIZE);
  memset((void*)(&prefix[fileKeyStart + FILE_KEY_SIZE]), 'V', IV_SIZE);
  memset((void*)(&prefix[fileKeyStart - CRC_SIZE]), 'C', CRC_SIZE);

#endif

  // key & IV have just been generated as the random data above
//  Slice key = Slice(prefix + fileKeyStart, FILE_KEY_SIZE);
//  Slice iv =  Slice(prefix + fileKeyStart + FILE_KEY_SIZE, IV_SIZE);

  // todo:
  // 1. Calculate key,iv CRC
  // 2. Encrypt key and iv with master key (AES ECB)
  // 3. Store calculated CRC
#if 0
  CTRCipherStream cipherStream(cipher_, prefixIV.data(), initialCounter);
  Status status;
  {
    PERF_TIMER_GUARD(encrypt_data_nanos);
    status = cipherStream.Encrypt(0, prefix + (2 * blockSize),
                                  prefixLength - (2 * blockSize));
  }
  if (!status.ok()) {
    return status;
  }
#endif
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

  // todo:
  // 1. Decrypt key and iv with master key (AES ECB)
  // 2. Calculate key,iv CRC
  // 3. validate if CRC is OK

  size_t fileKeyStart = KEY_MAGIC_SIZE + MASTER_KEY_ID_SIZE + S_UUID_SIZE + CRC_SIZE;

  Slice fileKey(prefix.data() + fileKeyStart, FILE_KEY_SIZE);
  Slice iv(prefix.data() + fileKeyStart + FILE_KEY_SIZE, IV_SIZE);

#if 0
  // Decrypt the encrypted part of the prefix, starting from block 2 (block 0, 1
  // with initial counter & IV are unencrypted)
  CTRCipherStream cipherStream(cipher_, iv.data(), initialCounter);
  Status status;
  {
    PERF_TIMER_GUARD(decrypt_data_nanos);
    status = cipherStream.Decrypt(0, (char*)prefix.data() + (2 * blockSize),
                                  prefix.size() - (2 * blockSize));
  }
  if (!status.ok()) {
    return status;
  }
#endif
  // Create cipher stream
  return CreateCipherStreamFromPrefix(fileKey, iv, result);
}

Status CTRAesEncryptionProvider::AddCipher(const std::string& descriptor, const char* /*cipher*/,
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