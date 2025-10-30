//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// Copyright (c) 2025, Siemens AG.
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "ipi.h"
#include "sm.h"
#include "sm_assert.h"
#include "pmp.h"
#include <crypto.h>
#include "enclave.h"
#include "platform-hook.h"
#include "sm-sbi-opensbi.h"
#include <sbi/sbi_string.h>
#include <sbi/riscv_locks.h>
#include <sbi/riscv_barrier.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_hart.h>

static int sm_init_done = 0;
static int sm_region_id = 0, os_region_id = 0;

#ifndef TARGET_PLATFORM_HEADER
#error "SM requires a defined platform to build"
#endif

// Special target platform header, set by configure script
#include TARGET_PLATFORM_HEADER

byte sm_hash[MDSIZE] = { 0, };
#if WITH_TINY_DICE
byte sm_cdi_l0[TINY_DICE_CDI_SIZE];
byte sm_cert_chain[TINY_DICE_MAX_CERT_CHAIN_SIZE];
uint32_t sm_cert_chain_size;
byte dev_secret_key[PRIVATE_KEY_SIZE] = { 0, };
static uint32_t deterministic_rng_counter;
static const uint8_t *deterministic_rng_salt;
static size_t deterministic_rng_salt_size;
#else /* WITH_TINY_DICE */
byte sm_signature[SIGNATURE_SIZE] = { 0, };
#endif /* WITH_TINY_DICE */
byte sm_public_key[PUBLIC_KEY_SIZE] = { 0, };
byte sm_private_key[PRIVATE_KEY_SIZE] = { 0, };
byte dev_public_key[PUBLIC_KEY_SIZE] = { 0, };

int osm_pmp_set(uint8_t perm)
{
  /* in case of OSM, PMP cfg is exactly the opposite.*/
  return pmp_set_keystone(os_region_id, perm);
}

static int smm_init(void)
{
  int region = -1;
  int ret = pmp_region_init_atomic(SMM_BASE, SMM_SIZE, PMP_PRI_TOP, &region, 0);
  if(ret)
    return -1;

  return region;
}

static int osm_init(void)
{
  int region = -1;
  int ret = pmp_region_init_atomic(0, -1UL, PMP_PRI_BOTTOM, &region, 1);
  if(ret)
    return -1;

  return region;
}

static int rng(uint8_t *dest, unsigned size)
{
  for (unsigned i = 0; i < size; i++) {
    dest[i] = sbi_sm_random();
  }
  return 1;
}

#if WITH_FHMQV
int sm_fhmqv(struct enclave_report *enclave_report)
{
  const uint8_t *peers_static_public_key;
  uint8_t peers_ephemeral_public_key[PUBLIC_KEY_SIZE];
  uint8_t our_ephemeral_public_key[PUBLIC_KEY_SIZE];
  uint8_t our_ephemeral_private_key[PRIVATE_KEY_SIZE];
  hash_ctx ctx;
  uint8_t de[MDSIZE];
  uint8_t sigma[MDSIZE];
  uint8_t ikm[4 * PUBLIC_KEY_SIZE];
  uint8_t okm[2 * MDSIZE];
#if WITH_FHMQVC
  sha_256_hmac_context_t hmac_ctx;
#endif /* WITH_FHMQVC */

  if (enclave_report->data_len
      != (PUBLIC_KEY_SIZE + PUBLIC_KEY_COMPRESSED_SIZE)) {
    return -1;
  }
  peers_static_public_key = enclave_report->data;
  uECC_decompress(enclave_report->data + PUBLIC_KEY_SIZE,
                  peers_ephemeral_public_key,
                  uECC_CURVE());
  if (!uECC_make_key(our_ephemeral_public_key,
                     our_ephemeral_private_key,
                     uECC_CURVE())) {
    return -1;
  }
  uECC_compress(our_ephemeral_public_key,
                enclave_report->ephemeral_public_key_compressed,
                uECC_CURVE());

  hash_init(&ctx);
  hash_extend(&ctx,
              peers_ephemeral_public_key,
              sizeof(peers_ephemeral_public_key));
  hash_extend(&ctx,
              our_ephemeral_public_key,
              sizeof(our_ephemeral_public_key));
  hash_extend(&ctx, peers_static_public_key, PUBLIC_KEY_SIZE);
  hash_extend(&ctx, sm_public_key, sizeof(sm_public_key));
  hash_finalize(de, &ctx);

  if (!uECC_shared_fhmqv_secret(sm_private_key,
                                our_ephemeral_private_key,
                                peers_static_public_key,
                                peers_ephemeral_public_key,
                                de + (sizeof(de) / 2),
                                de,
                                sigma,
                                uECC_CURVE())) {
    return -1;
  }
  sbi_memcpy(ikm, peers_static_public_key, PUBLIC_KEY_SIZE);
  sbi_memcpy(ikm + PUBLIC_KEY_SIZE,
             sm_public_key,
             sizeof(sm_public_key));
  sbi_memcpy(ikm + PUBLIC_KEY_SIZE + sizeof(sm_public_key),
             peers_ephemeral_public_key,
             sizeof(peers_ephemeral_public_key));
  sbi_memcpy(ikm + PUBLIC_KEY_SIZE
             + sizeof(sm_public_key)
             + sizeof(peers_ephemeral_public_key),
             our_ephemeral_public_key,
             sizeof(our_ephemeral_public_key));
  kdf(
#if WITH_FHMQVC
      NULL, 0,
#else /* WITH_FHMQVC */
      enclave_report->hash, sizeof(enclave_report->hash),
#endif /* WITH_FHMQVC */
      sigma, sizeof(sigma),
      ikm, sizeof(ikm),
      okm, sizeof(okm));
  sbi_memcpy(enclave_report->fhmqv_key,
             okm + sizeof(okm) / 2,
             sizeof(okm) / 2);
#if WITH_FHMQVC
  sha_256_hmac_init(&hmac_ctx, okm, sizeof(okm) / 2);
  sha_256_hmac_update(&hmac_ctx,
                      sm_public_key,
                      sizeof(sm_public_key));
  sha_256_hmac_update(&hmac_ctx,
                      our_ephemeral_public_key,
                      sizeof(our_ephemeral_public_key));
  sha_256_hmac_update(&hmac_ctx,
                      enclave_report->hash,
                      sizeof(enclave_report->hash));
  sha_256_hmac_finish(&hmac_ctx, enclave_report->servers_fhmqv_mic);
  sha_256_hmac_init(&hmac_ctx, okm, sizeof(okm) / 2);
  sha_256_hmac_update(&hmac_ctx, peers_static_public_key, PUBLIC_KEY_SIZE);
  sha_256_hmac_update(&hmac_ctx,
                      peers_ephemeral_public_key,
                      sizeof(peers_ephemeral_public_key));
  sha_256_hmac_finish(&hmac_ctx, enclave_report->clients_fhmqv_mic);
#endif /* WITH_FHMQVC */
  return 0;
}
#endif /* WITH_FHMQV */

int sm_sign(void* signature, byte digest[MDSIZE])
{
  if (!uECC_sign(sm_private_key, digest, MDSIZE, signature, uECC_CURVE())) {
    return -1;
  }
  return 0;
}

int sm_derive_sealing_key(unsigned char *key, const unsigned char *key_ident,
                          size_t key_ident_size,
                          const unsigned char *enclave_hash)
{
  unsigned char info[MDSIZE + key_ident_size];

  sbi_memcpy(info, enclave_hash, MDSIZE);
  sbi_memcpy(info + MDSIZE, key_ident, key_ident_size);

  /*
   * The key is derived without a salt because we have no entropy source
   * available to generate the salt.
   */
  return kdf(NULL, 0,
             (const unsigned char *)sm_private_key, PRIVATE_KEY_SIZE,
             info, MDSIZE + key_ident_size, key, SEALING_KEY_SIZE);
}

static void sm_print_hash(void)
{
  for (int i=0; i<MDSIZE; i++)
  {
    sbi_printf("%02x", (char) sm_hash[i]);
  }
  sbi_printf("\n");
}

/*
void sm_print_cert()
{
	int i;

	printm("Booting from Security Monitor\n");
	printm("Size: %d\n", sanctum_sm_size[0]);

	printm("============ PUBKEY =============\n");
	for(i=0; i<8; i+=1)
	{
		printm("%x",*((int*)sanctum_dev_public_key+i));
		if(i%4==3) printm("\n");
	}
	printm("=================================\n");

	printm("=========== SIGNATURE ===========\n");
	for(i=0; i<16; i+=1)
	{
		printm("%x",*((int*)sanctum_sm_signature+i));
		if(i%4==3) printm("\n");
	}
	printm("=================================\n");
}
*/

#if WITH_TINY_DICE
static int
deterministic_rng(uint8_t *dest, unsigned size)
{
  kdf(deterministic_rng_salt, deterministic_rng_salt_size,
      sm_cdi_l0, sizeof(sm_cdi_l0),
      (const uint8_t *)&deterministic_rng_counter,
      sizeof(deterministic_rng_counter),
      dest, size);
  deterministic_rng_counter++;
  return 1;
}

static int
encode_and_hash(
    const uint8_t reconstruction_data[ECC_CURVE_P_256_SIZE * 2],
    void *ptr,
    uint8_t certificate_hash[ECC_CURVE_P_256_SIZE])
{
  tiny_dice_cert_t cert;
  cbor_writer_state_t state;
  const uint8_t *head;
  const uint8_t *tail;

  tiny_dice_clear_cert(&cert);
  uECC_compress(reconstruction_data, cert.reconstruction_data, uECC_CURVE());
  cert.tci_digest = sm_hash;

  sbi_printf("Cert_L1 (at rest) {\n");
  sbi_printf("  subject: '',\n");
  sbi_printf("  issuer: %i (SHA-256),\n", cert.issuer_hash);
  sbi_printf("  curve: %i (secp256r1),\n", cert.curve);
  sbi_printf("  reconstruction-data: ");
  for (size_t i = 0; i < sizeof(cert.reconstruction_data); i++) {
    sbi_printf("%02x", cert.reconstruction_data[i]);
  }
  sbi_printf(",\n");
  sbi_printf("  tci: ");
  for (size_t i = 0; i < TINY_DICE_TCI_SIZE; i++) {
    sbi_printf("%02x", cert.tci_digest[i]);
  }
  sbi_printf("\n");
  sbi_printf("}\n");
  sbi_printf("Cert_L1 (in transit) {\n");
  sbi_printf("  reconstruction-data: ");
  for (size_t i = 0; i < sizeof(cert.reconstruction_data); i++) {
    sbi_printf("%02x", cert.reconstruction_data[i]);
  }
  sbi_printf(",\n");
  sbi_printf("  tci: 1\n");
  sbi_printf("}\n");

  cbor_init_writer(&state, sm_cert_chain, sizeof(sm_cert_chain));
  cbor_open_array(&state);

  /* write Cert_L1 */
  head = state.buffer;
  tiny_dice_write_cert(&state, &cert);
  tail = state.buffer;
  if (!head || !tail) {
    return 0;
  }

  /* hash Cert_L1 */
  {
    hash_ctx ctx;
    hash_init(&ctx);
    hash_extend(&ctx, head, tail - head);
    hash_finalize(ptr, &ctx);
  }
  sbi_memcpy(certificate_hash, ptr, MDSIZE);

  /* wrap up certificate chain */
  cbor_close_array(&state);
  sm_cert_chain_size = cbor_end_writer(&state);
  return sm_cert_chain_size != 0;
}

void init_tiny_dice(void)
{
  /* generate DeviceID */
  if(!uECC_make_key(dev_public_key,
                    dev_secret_key,
                    uECC_CURVE())) {
    sbi_printf("failed to generate DeviceID\n");
    sbi_hart_hang();
  }

  /* generate proto-AKey_L0 */
  deterministic_rng_salt = sm_hash;
  deterministic_rng_salt_size = sizeof(sm_hash);
  uint8_t proto_akey_l0_public_key[ECC_CURVE_P_256_SIZE * 2];
  uint8_t proto_akey_l0_secret_key[ECC_CURVE_P_256_SIZE];
  if (!uECC_make_key(proto_akey_l0_public_key,
                     proto_akey_l0_secret_key,
                     uECC_CURVE())) {
    sbi_printf("failed to generate proto-AKey_L0\n");
    sbi_hart_hang();
  }

  /* issue TinyDICE certificate */
  uint8_t private_key_reconstruction_data[ECC_CURVE_P_256_SIZE];
  uint8_t certificate_hash[MDSIZE];
  if (!uECC_generate_ecqv_certificate(proto_akey_l0_public_key,
                                      dev_secret_key,
                                      encode_and_hash,
                                      certificate_hash,
                                      private_key_reconstruction_data,
                                      uECC_CURVE())) {
    sbi_printf("failed to issue tinyDICE certificate\n");
    sbi_hart_hang();
  }

  /* generate AKey_L0 (= sm_public_key/sm_private_key) */
  if (!uECC_generate_ecqv_key_pair(proto_akey_l0_secret_key,
                                   certificate_hash,
                                   MDSIZE,
                                   private_key_reconstruction_data,
                                   sm_public_key,
                                   sm_private_key,
                                   uECC_CURVE())) {
    sbi_printf("failed to generate AKey_L0\n");
    sbi_hart_hang();
  }
}
#endif /* WITH_TINY_DICE */

void sm_init(bool cold_boot)
{
	// initialize SMM
  if (cold_boot) {
    /* only the cold-booting hart will execute these */
    sbi_printf("[SM] Initializing ... hart [%lx]\n", csr_read(mhartid));

    sbi_ecall_register_extension(&ecall_keystone_enclave);

    sm_region_id = smm_init();
    if(sm_region_id < 0) {
      sbi_printf("[SM] intolerable error - failed to initialize SM memory");
      sbi_hart_hang();
    }

    os_region_id = osm_init();
    if(os_region_id < 0) {
      sbi_printf("[SM] intolerable error - failed to initialize OS memory");
      sbi_hart_hang();
    }

    if (platform_init_global_once() != SBI_ERR_SM_ENCLAVE_SUCCESS) {
      sbi_printf("[SM] platform global init fatal error");
      sbi_hart_hang();
    }
    // Copy the keypair from the root of trust
    sm_copy_key();

    // Init the enclave metadata
    enclave_init_metadata();

    sm_init_done = 1;
    mb();
  }

  /* wait until cold-boot hart finishes */
  while (!sm_init_done)
  {
    mb();
  }

  /* below are executed by all harts */
  pmp_init();
  pmp_set_keystone(sm_region_id, PMP_NO_PERM);
  pmp_set_keystone(os_region_id, PMP_ALL_PERM);

  /* Fire platform specific global init */
  if (platform_init_global() != SBI_ERR_SM_ENCLAVE_SUCCESS) {
    sbi_printf("[SM] platform global init fatal error");
    sbi_hart_hang();
  }

  if (cold_boot) {
#if WITH_TINY_DICE
    uECC_set_rng(deterministic_rng);
    init_tiny_dice();
#endif /* WITH_TINY_DICE */
    uECC_set_rng(rng);
    sbi_printf("[SM] cold boot initialization done\n");
  }

  sbi_printf("[SM] Keystone security monitor has been initialized!\n");

  sm_print_hash();

  return;
  // for debug
  // sm_print_cert();
}
