//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// Copyright (c) 2025, Siemens AG.
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#ifndef sm_h
#define sm_h

#include <sbi/sbi_types.h>
#include "crypto.h"
#include "pmp.h"
#include "sm-sbi.h"
#include <sbi/riscv_encoding.h>

#include "sm_call.h"
#include "sm_err.h"

void sm_init(bool cold_boot);

/* platform specific functions */
#define ATTESTATION_KEY_LENGTH  64
void sm_retrieve_pubkey(void* dest);
#if WITH_FHMQV
struct enclave_report;
int sm_fhmqv(struct enclave_report *enclave_report);
#endif /* WITH_FHMQV */
int sm_sign(void* signature, byte digest[MDSIZE]);
int sm_derive_sealing_key(unsigned char *key,
                          const unsigned char *key_ident,
                          size_t key_ident_size,
                          const unsigned char *enclave_hash);

int osm_pmp_set(uint8_t perm);
#endif
