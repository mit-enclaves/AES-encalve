#include <api_enclave.h>
#include "crypto_stream.h"

#define CLEN 16

void enclave_entry() {
  const unsigned char k[crypto_stream_KEYBYTES];
  const unsigned char n[crypto_stream_NONCEBYTES];
  unsigned long long clen;
  clen = CLEN;
  unsigned char c[CLEN]; 

  crypto_stream(c,clen,n,k);

  sm_exit_enclave();
}
