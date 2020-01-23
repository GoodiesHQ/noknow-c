#include <noknow.h>

/* Example NoKnow Usage */

#define REQUIRE(x) if(!(x)) { exit(-1); }

static inline bool user_input(FILE *stream, char *ptr, size_t max, size_t *size)
{
  if(fgets(ptr, max, stream))
  {
    if(size != NULL)
    {
      *size = strlen(ptr);
    }
    return true;
  }
  return false;
}

static const char *hash_name = "SHA3_256";
static const char *curve_name = "SECP256R1";


int main() {
  zk_params params;
  zk_signature signature;
  zk_proof proof;
  const u8 data[] = "This can serve as a signed message.";

  char password[256];
  size_t password_len;

  fputs("Create password: ", stdout);
  REQUIRE(user_input(stdin, password, sizeof(password), &password_len));
  if(zk_create_params(&params, curve_name, hash_name, NULL)) // initialize ZK cryptosystem
  {
    if(zk_create_signature(&params, &signature, (u8*)password, password_len)) // create signature from secret
    {
      memset(password, 0, password_len); // clear password
      zk_display_aff(stdout, "Signature Point", &signature.p);

      fputs("Verify password: ", stdout);
      REQUIRE(user_input(stdin, password, sizeof(password), &password_len));
      if(zk_create_proof(&params, &proof, (u8*)password, password_len, data, sizeof(data)))
      {
        memset(password, 0, password_len); // clear password
        zk_display_nn(stdout, "Proof Digest", &proof.c);
        zk_display_nn(stdout, "Proof Point ", &proof.m);
        if(zk_verify_proof(&params, &signature, &proof, data, sizeof(data)))
        {
          return printf("Success!\n"), 0;
        } else {
          return printf("Failure!\n"), 1;
        }
      }
    }
  }
  return -1;
}
