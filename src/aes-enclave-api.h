#ifndef _AES_ENCLAVE_API_H_
#define _AES_ENCLAVE_API_H_

#include <stdint.h>
#include "crypto_stream.h"

typedef enum aes_opcode {
  OPCODE_NULL,
  OPCODE_ENCRYPT,
  OPCODE_DECRYPT,
} aes_opcode_t;

typedef enum aes_result {
  RESULT_NULL,
  RESULT_ENCRYPTED,
  RESULT_DECRYPTED,
  RESULT_INVALID,
  RESULT_BAD_LENGTH
} aes_result_t;

typedef struct aes_enclave_params {
  uint32_t magic;
  uint16_t message_len;
  uint8_t opcode;
  uint8_t result;
  uint8_t nonce[crypto_stream_NONCEBYTES];
  uint8_t message[4096 - 4];
} aes_enclave_params_t;

#endif
