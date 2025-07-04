//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// Copyright (c) 2025, Siemens AG.
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include <Report.hpp>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include "coap3/coap_internal.h"
#include "uECC.h"

using json11::Json;
std::string
Report::BytesToHex(byte* bytes, size_t len) {
  unsigned int i;
  std::string str;
  for (i = 0; i < len; i += 1) {
    std::stringstream ss;
    ss << std::setfill('0') << std::setw(2) << std::hex << (uintptr_t)bytes[i];

    str += ss.str();
  }
  return str;
}

void
Report::HexToBytes(byte* bytes, size_t len, std::string hexstr) {
  unsigned int i;
  for (i = 0; i < len; i++) {
    unsigned int data = 0;
    std::stringstream ss;
    ss << hexstr.substr(i * 2, 2);
    ss >> std::hex >> data;
    bytes[i] = (byte)data;
  }
}

void
Report::fromJson(std::string jsonstr) {
  std::string err;
  const auto json = Json::parse(jsonstr, err);

  std::string device_pubkey = json["device_pubkey"].string_value();
  HexToBytes(report.dev_public_key, PUBLIC_KEY_SIZE, device_pubkey);

  std::string sm_hash = json["security_monitor"]["hash"].string_value();
  HexToBytes(report.sm.hash, MDSIZE, sm_hash);
#if !WITH_TINY_DICE
  std::string sm_pubkey = json["security_monitor"]["pubkey"].string_value();
  HexToBytes(report.sm.public_key, PUBLIC_KEY_COMPRESSED_SIZE, sm_pubkey);
  std::string sm_signature =
      json["security_monitor"]["signature"].string_value();
  HexToBytes(report.sm.signature, SIGNATURE_SIZE, sm_signature);
#endif /* !WITH_TINY_DICE */

  std::string enclave_hash = json["enclave"]["hash"].string_value();
  HexToBytes(report.enclave.hash, MDSIZE, enclave_hash);
  report.enclave.data_len  = json["enclave"]["datalen"].int_value();
  std::string enclave_data = json["enclave"]["data"].string_value();
  HexToBytes(report.enclave.data, report.enclave.data_len, enclave_data);
#if WITH_FHMQVC
  std::string servers_fhmqv_mic = json["enclave"]["servers_fhmqv_mic"].string_value();
  HexToBytes(report.enclave.servers_fhmqv_mic, sizeof(report.enclave.servers_fhmqv_mic), servers_fhmqv_mic);
  std::string clients_fhmqv_mic = json["enclave"]["clients_fhmqv_mic"].string_value();
  HexToBytes(report.enclave.clients_fhmqv_mic, sizeof(report.enclave.clients_fhmqv_mic), clients_fhmqv_mic);
#elif !WITH_FHMQV
  std::string enclave_signature = json["enclave"]["signature"].string_value();
  HexToBytes(report.enclave.signature, SIGNATURE_SIZE, enclave_signature);
#endif /* !WITH_FHMQV */
}

void
Report::fromBytes(byte* bin) {
  std::memcpy(&report, bin, sizeof(struct report_t));
}

std::string
Report::stringfy() {
  if (report.enclave.data_len > ATTEST_DATA_MAXLEN) {
    return "{ \"error\" : \"invalid data length\" }";
  }
  auto json = Json::object{
      {"device_pubkey", BytesToHex(report.dev_public_key, PUBLIC_KEY_SIZE)},
      {
          "security_monitor",
          Json::object{
              {"hash", BytesToHex(report.sm.hash, MDSIZE)},
#if WITH_TINY_DICE
              {"cert", BytesToHex(report.sm.cert_chain, report.sm.cert_chain_size)}},
#else /* WITH_TINY_DICE */
              {"pubkey", BytesToHex(report.sm.public_key, PUBLIC_KEY_COMPRESSED_SIZE)},
              {"signature", BytesToHex(report.sm.signature, SIGNATURE_SIZE)}},
#endif /* WITH_TINY_DICE */
      },
      {
          "enclave",
          Json::object{
              {"hash", BytesToHex(report.enclave.hash, MDSIZE)},
              {"datalen", static_cast<int>(report.enclave.data_len)},
              {"data",
               BytesToHex(report.enclave.data, report.enclave.data_len)},
#if WITH_FHMQVC
              {"servers_fhmqv_mic",
               BytesToHex(report.enclave.servers_fhmqv_mic, sizeof(report.enclave.servers_fhmqv_mic))},
              {"clients_fhmqv_mic",
               BytesToHex(report.enclave.clients_fhmqv_mic, sizeof(report.enclave.clients_fhmqv_mic))},
#elif !WITH_FHMQV
              {"signature",
               BytesToHex(report.enclave.signature, SIGNATURE_SIZE)},
#endif /* !WITH_FHMQV */
          },
      },
  };

  return json11::Json(json).dump();
}

void
Report::printJson() {
  std::cout << stringfy() << std::endl;
}

void
Report::printPretty() {
  std::cout << "\t\t=== Security Monitor ===" << std::endl;
  std::cout << "Hash: " << BytesToHex(report.sm.hash, MDSIZE) << std::endl;
#if !WITH_TINY_DICE
  std::cout << "Pubkey: " << BytesToHex(report.sm.public_key, PUBLIC_KEY_COMPRESSED_SIZE)
            << std::endl;
  std::cout << "Signature: " << BytesToHex(report.sm.signature, SIGNATURE_SIZE)
            << std::endl;
#endif /* !WITH_TINY_DICE */
  std::cout << std::endl << "\t\t=== Enclave Application ===" << std::endl;
  std::cout << "Hash: " << BytesToHex(report.enclave.hash, MDSIZE) << std::endl;
#if WITH_FHMQVC
  std::cout << "Server's FHMQV MIC: "
            << BytesToHex(report.enclave.servers_fhmqv_mic, sizeof(report.enclave.servers_fhmqv_mic))
            << std::endl;
  std::cout << "Client's FHMQV MIC: "
            << BytesToHex(report.enclave.clients_fhmqv_mic, sizeof(report.enclave.clients_fhmqv_mic))
            << std::endl;
#elif !WITH_FHMQV
  std::cout << "Signature: "
            << BytesToHex(report.enclave.signature, SIGNATURE_SIZE)
            << std::endl;
#endif /* !WITH_FHMQV */
  std::cout << "Enclave Data: "
            << BytesToHex(report.enclave.data, report.enclave.data_len)
            << std::endl;
  std::cout << "\t\t-- Device pubkey --" << std::endl;
  std::cout << BytesToHex(report.dev_public_key, PUBLIC_KEY_SIZE) << std::endl;
}

byte*
Report::getEnclaveHash() {
    return report.enclave.hash;
}

byte*
Report::getSmHash() {
    return report.sm.hash;
}

int
Report::verify(
    const byte* expected_enclave_hash, const byte* expected_sm_hash,
    const byte* dev_public_key) {
  /* verify that enclave hash matches */
  int encl_hash_valid =
      memcmp(expected_enclave_hash, report.enclave.hash, MDSIZE) == 0;
  int sm_hash_valid = memcmp(expected_sm_hash, report.sm.hash, MDSIZE) == 0;

  int signature_valid = checkSignaturesOnly(dev_public_key);

  return encl_hash_valid && sm_hash_valid && signature_valid;
}

int
Report::checkSignaturesOnly(const byte* dev_public_key) {
  int sm_valid      = 0;
  int enclave_valid = 0;
  uint8_t scratchpad[MDSIZE + ATTEST_DATA_MAXLEN];
  uint8_t md[MDSIZE];
  uint8_t sm_public_key[PUBLIC_KEY_SIZE];

  /* verify SM report */
#if WITH_TINY_DICE
  sm_valid = 1;
#else /* WITH_TINY_DICE */
  memcpy(scratchpad, report.sm.hash, MDSIZE);
  memcpy(scratchpad + MDSIZE, report.sm.public_key, PUBLIC_KEY_COMPRESSED_SIZE);
  SHA_256.hash(scratchpad, MDSIZE + PUBLIC_KEY_COMPRESSED_SIZE, md);
  sm_valid = uECC_verify(dev_public_key, md, MDSIZE, report.sm.signature, uECC_CURVE());
#endif /* WITH_TINY_DICE */

  /* verify Enclave report */
#if WITH_FHMQV
  enclave_valid = 1;
#else /* WITH_FHMQV */
  uECC_decompress(report.sm.public_key, sm_public_key, uECC_CURVE());
  memcpy(scratchpad, report.enclave.hash, MDSIZE);
  memcpy(scratchpad + MDSIZE, report.enclave.data, report.enclave.data_len);
  SHA_256.hash(scratchpad, MDSIZE + report.enclave.data_len, md);
  enclave_valid = uECC_verify(sm_public_key, md, MDSIZE, report.enclave.signature, uECC_CURVE());
#endif /* WITH_FHMQV */

  return sm_valid && enclave_valid;
}

void*
Report::getDataSection() {
  return report.enclave.data;
}

size_t
Report::getDataSize() {
  return report.enclave.data_len;
}
