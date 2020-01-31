#include <noknow.h>
#include <noknow/debug.h>
#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>

/* Example NoKnow Usage */
#define INPUT_BLOCK_SIZE 10

#define REQUIRE(x) if(!(x)) { exit(-1); }

char *user_input(size_t *len);
char *arbitrary_input(FILE *stream, char delim, size_t *len);

char *user_input(size_t *len)
{
  return arbitrary_input(stdin, '\n', len);
}

char *arbitrary_input(FILE *stream, char delim, size_t *input_len) {
  char *buf = NULL, *tmp, c;
  size_t allocated = 0, used = 0;

  while((c = (char)fgetc(stream))) {
    if(used == allocated) {
      if((tmp = realloc(buf, allocated += INPUT_BLOCK_SIZE)) == NULL) {
        fprintf(stderr, "Allocation failure\n");
        free(buf);
        return NULL;
      }
      buf = tmp;
    }
    if(c == delim) {
      if(c != EOF) { // special case, EOF means end of buffer, no need to add null terminator
        buf[used++] = '\0';
      }
      break;
    } else {
      buf[used++] = c;
    }
  }

  if(input_len != NULL) {
    *input_len = used;
  }
  return buf;
}


int err(int code) {
  fputs("Supported Curves:", stdout);
  zk_list_curves(stdout);

  fputs("Supported Hashes:", stdout);
  zk_list_hashes(stdout);

  return code;
}

char *get_curve(void)
{
  char *curve_name;
  size_t len, i;
  fputs("Enter the curve name: ", stdout);
  fflush(stdout);
  curve_name = user_input(&len);
  for(i = 0; i < len; ++i)
  {
    curve_name[i] = tolower(curve_name[i]);
  }
  return curve_name;
}

char *get_hash(void)
{
  char *hash_name;
  size_t len, i;
  fputs("Enter the hash name: ", stdout);
  fflush(stdout);
  hash_name = user_input(&len);
  for(i = 0; i < len; ++i)
  {
    hash_name[i] = toupper(hash_name[i]);
  }
  return hash_name;
}


int main() {
  static const char *hash_name = "SHA512";
  static const char *curve_name = "secp256r1";

  zk_params params;
  zk_signature signature;
  zk_proof proof;
  uint8_t salt[SALT_SIZE] = { 0 };
  uint8_t secret[] = "Passw0rd!123";

  UNUSED(user_input);
  UNUSED(salt);
  UNUSED(secret);

  //const mbedtls_ecp_curve_info *curve_info;
  //const mbedtls_md_info_t *hash_info;

  if(!zk_is_supported_curve_name(curve_name, NULL))
  {
    debugf("Invalid Curve '%s'\n", curve_name);
    return err(-1);
  }

  if(!zk_is_supported_hash_name(hash_name, NULL))
  {
    debugf("Invalid Hash '%s'\n", hash_name);
    return err(-1);
  }

  printf("Supported!\n");
  fflush(stdout);
  if(zk_create_params(&params, curve_name, hash_name, salt))
  {
    printf("Created Params!\n");
    fflush(stdout);
    if(zk_create_signature(&params, &signature, secret, sizeof(secret)))
    {
      printf("Created Signature!\n");
      zk_display_point(stdout, "Signature Point", &params.curve, &signature.p);
      fflush(stdout);
      if(zk_create_proof(&params, &proof, secret, sizeof(secret), NULL, 0))
      {
        printf("Proof:\n");
        zk_display_mpi(stdout, "C", &proof.c);
        zk_display_mpi(stdout, "M", &proof.m);

        if(zk_verify_proof(&params, &signature, &proof, NULL, 0)){
          printf("Success!\n");
        } else {
          printf("Failure!\n");
        }
        if(1) return 0;
      }
      zk_destroy_signature(&signature);
    }
    zk_destroy_params(&params);
  }else{
    debugf("Failed to create parameters\n");
  }

  return 0;
}
