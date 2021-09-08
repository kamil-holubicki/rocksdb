//  Copyright (c) 2016-present, Facebook, Inc.  All rights reserved.
//  This source code is licensed under both the GPLv2 (found in the
//  COPYING file in the root directory) and Apache 2.0 License
//  (found in the LICENSE.Apache file in the root directory).

#pragma once

#if !defined(ROCKSDB_LITE)

#include "rocksdb/env_encryption.h"

namespace ROCKSDB_NAMESPACE {

class Stream_cipher;
// CTRCipherStream implements BlockAccessCipherStream using an
// Counter operations mode.
// See https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation
//
// Note: This implementation of BlockAccessCipherStream uses AES-CRT encryption
// with SSL backend
class CTRAesCipherStream final : public BlockAccessCipherStream {
 private:
  std::unique_ptr<Stream_cipher> m_encryptor;
  std::unique_ptr<Stream_cipher> m_decryptor;
  uint64_t m_encryptPosition;
  uint64_t m_decryptPosition;

 public:
  CTRAesCipherStream(const char* file_key, const char* iv);
  virtual ~CTRAesCipherStream();

  // BlockSize returns the size of each block supported by this cipher stream.
  size_t BlockSize() override;

  // Encrypt one or more (partial) blocks of data at the file offset.
  // Length of data is given in dataSize.
  Status Encrypt(uint64_t fileOffset, char* data, size_t dataSize) override;

  // Decrypt one or more (partial) blocks of data at the file offset.
  // Length of data is given in dataSize.
  Status Decrypt(uint64_t fileOffset, char* data, size_t dataSize) override;

 protected:
  // Allocate scratch space which is passed to EncryptBlock/DecryptBlock.
  void AllocateScratch(std::string&) override;

  // Encrypt a block of data at the given block index.
  // Length of data is equal to BlockSize();
  Status EncryptBlock(uint64_t blockIndex, char* data, char* scratch) override;

  // Decrypt a block of data at the given block index.
  // Length of data is equal to BlockSize();
  Status DecryptBlock(uint64_t blockIndex, char* data, char* scratch) override;
};

// This encryption provider uses a CTR cipher stream, with a given block cipher
// and IV.
//
// CTR AES encryption provider
class CTRAesEncryptionProvider : public EncryptionProvider {
 private:
  static const char* kKeyMagic;
  static constexpr int KEY_MAGIC_SIZE     = 4;
  static constexpr int MASTER_KEY_ID_SIZE = 4;
  static constexpr int S_UUID_SIZE        = 36;
  static constexpr int CRC_SIZE           = 4;
  static constexpr int FILE_KEY_SIZE      = 32;
  static constexpr int IV_SIZE            = 16;

 protected:
  // For optimal performance when using direct IO, the prefix length should be a
  // multiple of the page size. This size is to ensure the first real data byte
  // is placed at largest known alignment point for direct io.
  const static size_t defaultPrefixLength = 4096;

 public:
  explicit CTRAesEncryptionProvider() {};
  virtual ~CTRAesEncryptionProvider() {}

  static const char* kCTRAesProviderName;

  const char* Name() const override;

  // GetPrefixLength returns the length of the prefix that is added to every
  // file
  // and used for storing encryption options.
  // For optimal performance when using direct IO, the prefix length should be a
  // multiple of the page size.
  size_t GetPrefixLength() const override;

  // CreateNewPrefix initialized an allocated block of prefix memory
  // for a new file.
  Status CreateNewPrefix(const std::string& fname, char* prefix,
                         size_t prefixLength) const override;

  // CreateCipherStream creates a block access cipher stream for a file given
  // given name and options.
  Status CreateCipherStream(
      const std::string& fname, const EnvOptions& options, Slice& prefix,
      std::unique_ptr<BlockAccessCipherStream>* result) override;

  Status AddCipher(const std::string& descriptor, const char* /*cipher*/,
                   size_t /*len*/, bool /*for_write*/) override;

  std::string GetMarker() const override;

 protected:
  Status TEST_Initialize() override;

  // CreateCipherStreamFromPrefix creates a block access cipher stream for a
  // file given
  // given name and options. The given prefix is already decrypted.
  virtual Status CreateCipherStreamFromPrefix(
      const Slice& key, const Slice& iv,
      std::unique_ptr<BlockAccessCipherStream>* result);
};
}  // namespace ROCKSDB_NAMESPACE

#endif  // !defined(ROCKSDB_LITE)
