//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "ipi.h"
#include "sm.h"
#include "pmp.h"
#include <crypto.h>
#include "enclave.h"
#include "platform-hook.h"
#include "sm-sbi-opensbi.h"
#include "coap3/coap_internal.h"
#include <sbi/sbi_string.h>
#include <sbi/riscv_locks.h>
#include <sbi/riscv_barrier.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_hart.h>
#include "coap3/coap_internal.h"
#include "micro-ecc/uECC.h"
#include "sm_assert.h"

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

#if WITH_TRAP
int sm_fhmqv(unsigned char *enclaves_fhmqv_mic,
    unsigned char *clients_fhmqv_mic,
    unsigned char *fhmqv_key,
    unsigned char *data, size_t len,
    const unsigned char *enclave_hash)
{
  const uint8_t *spka; /* client's static public key */
  uint8_t epka[PUBLIC_KEY_SIZE]; /* clients ephemeral public key */
  uint8_t epkb[PUBLIC_KEY_SIZE];
  sha_256_context_t ctx;
  byte d[MDSIZE];
  byte e[MDSIZE];
  uint8_t eskb[PRIVATE_KEY_SIZE];
  uint8_t sigma[MDSIZE];
  uint8_t ikm[4 * PUBLIC_KEY_SIZE];
  uint8_t okm[2 * MDSIZE];
  uint8_t auth_data[2 * PUBLIC_KEY_SIZE + MDSIZE];

  if (len != (PUBLIC_KEY_SIZE + 2 * PUBLIC_KEY_COMPRESSED_SIZE)) {
    return -1;
  }
  spka = data;
  data += PUBLIC_KEY_SIZE;
  len -= PUBLIC_KEY_SIZE;
  uECC_decompress(data, epka, uECC_CURVE());
  data += PUBLIC_KEY_COMPRESSED_SIZE;
  len -= PUBLIC_KEY_COMPRESSED_SIZE;
  if (!uECC_make_key(epkb, eskb, uECC_CURVE())) {
    return -1;
  }
  uECC_compress(epkb, data, uECC_CURVE());
  data += PUBLIC_KEY_COMPRESSED_SIZE;
  len -= PUBLIC_KEY_COMPRESSED_SIZE;

  SHA_256.init(&ctx);
  SHA_256.update(&ctx, epka, PUBLIC_KEY_SIZE);
  SHA_256.update(&ctx, epkb, PUBLIC_KEY_SIZE);
  SHA_256.update(&ctx, spka, PUBLIC_KEY_SIZE);
  SHA_256.update(&ctx, sm_public_key, PUBLIC_KEY_SIZE);

  SHA_256.finalize(&ctx, d);
  sbi_memcpy(e + MDSIZE / 2, d, MDSIZE / 2);
  sbi_memset(e, 0, MDSIZE / 2);
  sbi_memset(d, 0, MDSIZE / 2);

  if(!uECC_shared_fhmqv_secret(sigma,
      sm_private_key,
      eskb,
      spka,
      epka,
      e,
      d,
      uECC_CURVE())) {
    return -1;
  }
  sbi_memcpy(ikm, spka, PUBLIC_KEY_SIZE);
  sbi_memcpy(ikm + PUBLIC_KEY_SIZE, sm_public_key, PUBLIC_KEY_SIZE);
  sbi_memcpy(ikm + 2 * PUBLIC_KEY_SIZE, epka, PUBLIC_KEY_SIZE);
  sbi_memcpy(ikm + 3 * PUBLIC_KEY_SIZE, epkb, PUBLIC_KEY_SIZE);
  sha_256_hkdf(NULL, 0, /* TODO use salt */
      sigma, sizeof(sigma),
      ikm, sizeof(ikm),
      okm, sizeof(okm));
  sbi_memcpy(fhmqv_key, okm + MDSIZE, MDSIZE);
  sbi_memcpy(auth_data, sm_public_key, PUBLIC_KEY_SIZE);
  sbi_memcpy(auth_data + PUBLIC_KEY_SIZE, epkb, PUBLIC_KEY_SIZE);
  sbi_memcpy(auth_data + 2 * PUBLIC_KEY_SIZE, enclave_hash, MDSIZE);
  sha_256_hmac(okm, MDSIZE, auth_data, sizeof(auth_data), enclaves_fhmqv_mic);
  sbi_memcpy(auth_data, spka, PUBLIC_KEY_SIZE);
  sbi_memcpy(auth_data + PUBLIC_KEY_SIZE, epka, PUBLIC_KEY_SIZE);
  sha_256_hmac(okm, MDSIZE, auth_data, 2 * PUBLIC_KEY_SIZE, clients_fhmqv_mic);
  return 0;
}
#endif /* WITH_TRAP */

int sm_sign(void* signature, const void* data, size_t len)
{
  unsigned char md[MDSIZE];

  SHA_256.hash(data, len, md);
  if (!uECC_sign(sm_private_key, md, sizeof(md), signature, uECC_CURVE())) {
    return -1;
  }
  return 0;
}

void sm_derive_sealing_key(unsigned char *key, const unsigned char *key_ident,
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
  kdf(NULL, 0,
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
  sha_256_hkdf(NULL, 0,
               sm_cdi_l0, sizeof(sm_cdi_l0),
               (const uint8_t *)&deterministic_rng_counter,
               sizeof(deterministic_rng_counter),
               dest, size);
  deterministic_rng_counter++;
  return 1;
}

static int
encode_and_hash(
    uint8_t certificate_hash[uECC_BYTES],
    const uint8_t reconstruction_data[uECC_BYTES * 2],
    void *ptr)
{
  tiny_dice_cert_t cert;
  cbor_writer_state_t state;
  const uint8_t *tail;
  const uint8_t *head;

  tiny_dice_clear_cert(&cert);
  uECC_compress(reconstruction_data,
                cert.compressed_reconstruction_data,
                uECC_CURVE());
  cert.tci_digest = sm_hash;

  cbor_init_writer(&state, sm_cert_chain, sizeof(sm_cert_chain));
  tail = cbor_open_array(&state);

  /* write Cert_L1 */
  head = tiny_dice_prepend_cert(&state, &cert);
  if (!head) {
    return 1;
  }

  /* hash Cert_L1 */
  SHA_256.hash(head, tail - head, ptr);
  sbi_memcpy(certificate_hash, ptr, SHA_256_DIGEST_LENGTH);

  /* wrap up certificate chain */
  head = cbor_wrap_array(&state);
  if (!head) {
    return 1;
  }
  sm_cert_chain_size = tail - head;
  sbi_memmove(sm_cert_chain, head, sm_cert_chain_size);
  return 0;
}

void init_tiny_dice(void)
{
  deterministic_rng_counter = 0;
  uECC_set_rng(deterministic_rng);

  /* generate DeviceID */
  if(!uECC_make_key(dev_public_key,
                    dev_secret_key,
                    uECC_CURVE())) {
    sbi_printf("failed to generate DeviceID\n");
    sbi_hart_hang();
  }

  /* generate proto-AKey_L0 */
  uint8_t proto_akey_l0_public_key[uECC_BYTES * 2];
  uint8_t proto_akey_l0_secret_key[uECC_BYTES];
  if (!uECC_make_key(proto_akey_l0_public_key,
                     proto_akey_l0_secret_key,
                     uECC_CURVE())) {
    sbi_printf("failed to generate proto-AKey_L0\n");
    sbi_hart_hang();
  }

  /* issue tinyDICE certificate */
  uint8_t public_key_reconstruction_data[uECC_BYTES * 2];
  uint8_t private_key_reconstruction_data[uECC_BYTES];
  uint8_t certificate_hash[SHA_256_DIGEST_LENGTH];
  if (!uECC_generate_ecqv_certificate(public_key_reconstruction_data,
                                      private_key_reconstruction_data,
                                      proto_akey_l0_public_key,
                                      dev_secret_key,
                                      encode_and_hash,
                                      certificate_hash,
                                      uECC_CURVE())) {
    sbi_printf("failed to issue tinyDICE certificate\n");
    sbi_hart_hang();
  }

  /* generate AKey_L0 (= sm_private_key/sm_public_key) */
  if (!uECC_generate_ecqv_key_pair(sm_private_key,
                                   sm_public_key,
                                   proto_akey_l0_secret_key,
                                   certificate_hash,
                                   SHA_256_DIGEST_LENGTH,
                                   private_key_reconstruction_data,
                                   uECC_CURVE())) {
    sbi_printf("failed to generate AKey_L0\n");
    sbi_hart_hang();
  }

  uint8_t restored_public_key[PUBLIC_KEY_SIZE];
  sm_assert(uECC_restore_ecqv_public_key(restored_public_key,
                                         certificate_hash,
                                         SHA_256_DIGEST_LENGTH,
                                         public_key_reconstruction_data,
                                         dev_public_key,
                                         uECC_CURVE()));
  sm_assert(!sbi_memcmp(restored_public_key,
                        sm_public_key,
                        sizeof(restored_public_key)));

  uECC_set_rng(rng);
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

#if WITH_TINY_DICE
  init_tiny_dice();
#else /* WITH_TINY_DICE */
  uECC_set_rng(rng);
#endif /* WITH_TINY_DICE */

  sbi_printf("[SM] Keystone security monitor has been initialized!\n");

  sm_print_hash();

  return;
  // for debug
  // sm_print_cert();
}
