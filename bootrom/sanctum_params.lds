. = 0x801ff000; /* the last page before the payload */

/* ## manufacturer_keys : */

/* 32 Bytes : manufacturer public key */
PROVIDE( sanctum_m_public_key = . );
. += 0x20;

/* 64 Bytes : device public key */
PROVIDE( sanctum_dev_public_key = . );
. += 0x40;

/* 32 Bytes : device secret key */
PROVIDE( sanctum_dev_secret_key = . );
. += 0x20;

/* ## security_monitor_keys : */

/* 32 Bytes : security monitor hash */
PROVIDE( sanctum_sm_hash = . );
. += 0x20;

/* 64 Bytes : security monitor public key */
PROVIDE( sanctum_sm_public_key = . );
. += 0x40;

/* 32 Bytes : security monitor secret key */
PROVIDE( sanctum_sm_secret_key = . );
. += 0x20;

/* 64 Bytes : security monitor's signature by device */
PROVIDE( sanctum_sm_signature = . );
. += 0x40;

/* 32 Bytes : CDI_L0 */
PROVIDE( tiny_dice_cdi_l0 = . );
. += 0x20;
