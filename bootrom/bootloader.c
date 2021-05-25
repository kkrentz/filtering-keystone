#include <stddef.h>
#include "sha-256.h"
#include "string.h"
#include "uECC.h"

typedef unsigned char byte;

// Sanctum header fields in DRAM
extern byte sanctum_dev_public_key[uECC_BYTES * 2];
extern byte sanctum_dev_secret_key[uECC_BYTES];
unsigned int sanctum_sm_size = 0x1ff000;
extern byte sanctum_sm_hash[SHA_256_DIGEST_LENGTH];
extern byte sanctum_sm_public_key[uECC_BYTES * 2];
extern byte sanctum_sm_secret_key[uECC_BYTES];
extern byte sanctum_sm_signature[uECC_BYTES * 2];
#define DRAM_BASE 0x80000000

/* Update this to generate valid entropy for target platform*/
inline byte random_byte(unsigned int i) {
#warning Bootloader does not have entropy source, keys are for TESTING ONLY
  return 0xac + (0xdd ^ i);
}

void bootloader() {
	//*sanctum_sm_size = 0x200;
  // Reserve stack space for secrets
  byte scratchpad[128];
  byte md[SHA_256_DIGEST_LENGTH];

  // TODO: on real device, copy boot image from memory. In simulator, HTIF writes boot image
  // ... SD card to beginning of memory.
  // sd_init();
  // sd_read_from_start(DRAM, 1024);

  /* Gathering high quality entropy during boot on embedded devices is
   * a hard problem. Platforms taking security seriously must provide
   * a high quality entropy source available in hardware. Platforms
   * that do not provide such a source must gather their own
   * entropy. See the Keystone documentation for further
   * discussion. For testing purposes, we have no entropy generation.
  */

  // Create a random seed for keys and nonces from TRNG
  for (unsigned int i=0; i<32; i++) {
    scratchpad[i] = random_byte(i);
  }

  /* On a real device, the platform must provide a secure root device
     keystore. For testing purposes we hardcode a known private/public
     keypair */
  // TEST Device key
  #include "use_test_keys.h"
  
  // Derive {SK_D, PK_D} (device keys) from a 32 B random seed
  //ed25519_create_keypair(sanctum_dev_public_key, sanctum_dev_secret_key, scratchpad);

  // Measure SM
  sha_256_hash((void*)DRAM_BASE, sanctum_sm_size, sanctum_sm_hash);

  // Derive {SK_D, PK_D} (device keys) from the first 32 B of the hash (NIST endorses SHA512 truncation as safe)
  if (!uECC_make_key(sanctum_sm_public_key, sanctum_sm_secret_key, uECC_CURVE())) {
    while(1);
  }

  // Endorse the SM
  memcpy(scratchpad, sanctum_sm_hash, SHA_256_DIGEST_LENGTH);
  memcpy(scratchpad + SHA_256_DIGEST_LENGTH, sanctum_sm_public_key, uECC_BYTES * 2);
  sha_256_hash(scratchpad, SHA_256_DIGEST_LENGTH + uECC_BYTES * 2, md);
  // Sign (H_SM, PK_SM) with SK_D
  if (!uECC_sign(sanctum_dev_secret_key, md, SHA_256_DIGEST_LENGTH, sanctum_sm_signature, uECC_CURVE())) {
    while(1);
  }

  // Clean up
  // Erase SK_D
  memset((void*)sanctum_dev_secret_key, 0, sizeof(*sanctum_dev_secret_key));

  // caller will clean core state and memory (including the stack), and boot.
  return;
}
