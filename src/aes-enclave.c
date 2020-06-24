#include <stdlib.h>
#include <api_enclave.h>
#include <clib.h>

#include "aes-enclave-api.h"
#include "aes-enclave-key.h"

uint8_t nonce[crypto_stream_NONCEBYTES];

void enclave_entry() {
    aes_enclave_params_t *params = (void *)0xF000000;

    uint8_t opcode = params->opcode;
    switch (opcode) {
    case OPCODE_ENCRYPT:
    case OPCODE_DECRYPT: {
	if (params->message_len > sizeof(params->message)) {
	    params->result = RESULT_BAD_LENGTH;
	} else {
	    if (opcode == OPCODE_ENCRYPT) {
		// due to physaddr lookup hack, cannot pass a pointer to the shared pages
		sm_random((uintptr_t)nonce, sizeof(nonce));
		memcpy(params->nonce, nonce, sizeof(nonce));
	    }
	    crypto_stream_xor(params->message, params->message, params->message_len, params->nonce, aes_enclave_key);
	    params->result = (opcode == OPCODE_ENCRYPT) ? RESULT_ENCRYPTED : RESULT_DECRYPTED;
	}
	break;
    }
    default:
	params->result = RESULT_INVALID;
    }

    sm_exit_enclave();
}
