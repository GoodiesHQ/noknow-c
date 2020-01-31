#include <noknow/debug.h>
#include <noknow/utils/security.h>
#include <string.h>

#if (defined(__unix__) || defined(__APPLE__))
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int fimport(unsigned char *buf, size_t buflen, const char *path) {
  size_t rem = buflen, copied = 0;
  ssize_t ret;
  int fd;

  if ((fd = open(path, O_RDONLY)) == -1)
  {
    debugf("Unable to open input file %s\n", path);
    return -1;
  }

  while (rem) {
    if ((ret = read(fd, buf + copied, rem)) <= 0) {
      break;
    }
    rem -= ret;
    copied += ret;
  }
  close(fd);
  return (copied == buflen) ? 0 : -1;
}

int get_random(unsigned char *buf, size_t len) {
  return fimport(buf, len, "/dev/urandom");
}

#elif defined(__WIN32__)

#include <windows.h>
#include <wincrypt.h>

int get_random(unsigned char *buf, size_t len) {
  int ret;
  HCRYPTPROV hCryptProv = 0;

  if(CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) == FALSE) {
    return -1;
  }

  ret = CryptGenRandom(hCryptProv, len, buf) == FALSE ? -1 : 0;
  CryptReleaseContext(hCryptProv, 0);
  return ret;
}
#else
#error "Unsupported Platform System"
#endif

mbedtls_entropy_context *zk_entropy(void) {
  static bool initialized = false;
  static mbedtls_entropy_context ectx;
  if(!initialized) {
    mbedtls_entropy_init(&ectx);
    initialized = true;
  }
  return &ectx;
}

/*
 * Determine if the name of the curve is supported
 */
void zk_list_hashes(FILE *stream) {
  const mbedtls_md_type_t *mdt;
  const mbedtls_md_info_t *info;
  size_t i = 0;
  mdt = (mbedtls_md_type_t*)mbedtls_md_list();
  do{
    info = mbedtls_md_info_from_type(mdt[i]);
    fputs(mbedtls_md_get_name(info), stream);
    fputc(' ', stream);
  }while(mdt[++i] != MBEDTLS_MD_NONE);
  fputc('\n', stream);
}


void zk_list_curves(FILE *stream) {
  const mbedtls_ecp_curve_info *curves;
  size_t i = 0;
  curves = mbedtls_ecp_curve_list();
  do {
    fprintf(stream, "%s ", curves[i].name);
    fputs(curves[i].name, stream);
    fputc(' ', stream);
  }while(curves[++i].grp_id != MBEDTLS_ECP_DP_NONE);
  fputc('\n', stream);
}


bool zk_is_supported_curve_name(const char *curve_name, const mbedtls_ecp_curve_info ** curve_info) {
  const mbedtls_ecp_curve_info *info;
  info = mbedtls_ecp_curve_info_from_name(curve_name);
  if(info != NULL)
  {
    if(curve_info != NULL)
    {
      *curve_info = info;
    }
    return true;
  }
  return false;
}


bool zk_is_supported_hash_name(const char *hash_name, const mbedtls_md_info_t **hash_info)
{
  const mbedtls_md_info_t *info;
  info = mbedtls_md_info_from_string(hash_name);
  if(info != NULL)
  {
    if(hash_info != NULL)
    {
      *hash_info = info;
    }
    return true;
  }
  return false;
}


/*
 * Constant-time buffer comparison algorithm
 */
bool zk_are_equal(const uint8_t * const buf1, const uint8_t * const buf2, size_t buflen)
{
  uint8_t check = 0;
  size_t i;
  for(i = 0; i < buflen; ++i)
  {
    check |= buf1[i] ^ buf2[i];
  }
  return check == 0;
}
