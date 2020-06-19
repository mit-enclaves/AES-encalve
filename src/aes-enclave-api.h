#ifndef _AES_ENCLAVE_API_H_
#define _AES_ENCLAVE_API_H_

#include <stdint.h>
#include "crypto_stream.h"

enum opcode_result {
  OPCODE_NULL,
  OPCODE_ENCRYPT,
  OPCODE_DECRYPT,
  OPCODE_ENCRYPTED,
  OPCODE_DECRYPTED,
  OPCODE_INVALID
};

typedef struct aes_enclave_params {
  uint16_t message_len;
  uint8_t nonce[crypto_stream_NONCEBYTES];
  uint8_t opcode_result;
  uint8_t message[4096 - 4];
} aes_enclave_params_t;

#endif
