#ifndef COAP_INTERNAL_H_
#define COAP_INTERNAL_H_

#ifdef KEYSTONE_SM
#include "libcoap/include/oscore-ng/oscore_ng_cbor.h"
#include "libcoap/include/oscore-ng/oscore_ng_sha_256.h"
#include "libcoap/include/oscore-ng/oscore_ng_tiny_dice.h"
#else /* KEYSTONE_SM */
#include "libcoap/include/oscore-ng/oscore_ng_sha_256.h"
#endif /* KEYSTONE_SM */

#endif /* COAP_INTERNAL_H_ */
