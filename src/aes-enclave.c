#include <api_enclave.h>
#include <clib.h>

#include "aes-enclave-api.h"
#include "aes-enclave-key.h"

void enclave_entry() {
    aes_enclave_params_t *params = (void *)0xF000000;

    uint8_t opcode = params->opcode_result;
    switch (opcode) {
    case OPCODE_ENCRYPT:
    case OPCODE_DECRYPT: {
	if (params->message_len > sizeof(params->message)) {
	    params->opcode_result = OPCODE_INVALID;
	} else {
	    if (opcode == OPCODE_ENCRYPT) {
		uint64_t random;
		for (int i = 0; i < sizeof(params->nonce); i += sizeof(random)) {
		    random = sm_random();
		    memcpy(params->nonce + i, (uint8_t *)random, sizeof(random));
		}
	    }
	    crypto_stream(params->message, params->message_len, params->nonce, aes_enclave_key);
	    params->opcode_result = (opcode == OPCODE_ENCRYPT) ? OPCODE_ENCRYPTED : OPCODE_DECRYPTED;
	}
	break;
    }
    default:
	params->opcode_result = OPCODE_INVALID;
    }

    sm_exit_enclave();
}
