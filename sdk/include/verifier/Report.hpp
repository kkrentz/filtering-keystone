//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// Copyright (c) 2025, Siemens AG.
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#pragma once

#include <iostream>
#include <string>
#include "Keys.hpp"
#include "verifier/json11.h"

struct enclave_report_t {
  byte hash[MDSIZE];
  uint64_t data_len;
  byte data[ATTEST_DATA_MAXLEN];
#if WITH_FHMQV
  byte ephemeral_public_key_compressed[PUBLIC_KEY_COMPRESSED_SIZE];
  byte fhmqv_key[MDSIZE];
#if WITH_FHMQVC
  byte servers_fhmqv_mic[MDSIZE];
  byte clients_fhmqv_mic[MDSIZE];
#endif /* WITH_FHMQVC */
#else /* WITH_FHMQV */
  byte signature[SIGNATURE_SIZE];
#endif /* WITH_FHMQV */
};

struct sm_report_t {
  byte hash[MDSIZE];
#if WITH_TINY_DICE
  byte cert_chain[TINY_DICE_MAX_CERT_CHAIN_SIZE];
  uint32_t cert_chain_size;
#else /* WITH_TINY_DICE */
  byte public_key[PUBLIC_KEY_COMPRESSED_SIZE];
  byte signature[SIGNATURE_SIZE];
#endif /* WITH_TINY_DICE */
};

struct report_t {
  struct enclave_report_t enclave;
  struct sm_report_t sm;
  byte dev_public_key[PUBLIC_KEY_SIZE];
};

class Report {
 private:
  struct report_t report;

 public:
  std::string BytesToHex(byte* bytes, size_t len);
  void HexToBytes(byte* bytes, size_t len, std::string hexstr);
  void fromJson(std::string json);
  void fromBytes(byte* bin);
  std::string stringfy();
  void printJson();
  void printPretty();
  int verify(
      const byte* expected_enclave_hash, const byte* expected_sm_hash,
      const byte* dev_public_key);
  int checkSignaturesOnly(const byte* dev_public_key);
  void* getDataSection();
  size_t getDataSize();
  byte* getEnclaveHash();
  byte* getSmHash();
};
