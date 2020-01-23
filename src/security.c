#include <stdlib.h>

#include <libec.h>
#include <hash/hash_algs.h>

#include <noknow/utils/security.h>


#if (defined(__unix__) || defined(__APPLE__))
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int fimport(unsigned char *buf, u16 buflen, const char *path)
{
        u16 rem = buflen, copied = 0;
        ssize_t ret;
        int fd;

        fd = open(path, O_RDONLY);
        if (fd == -1) {
                printf("Unable to open input file %s\n", path);
                return -1;
        }

        while (rem) {
                ret = (int)read(fd, buf + copied, rem);
                if (ret <= 0) {
                        break;
                } else {
                        rem -= (u16)ret;
                        copied += (u16)ret;
                }
        }

        close(fd);

        return (copied == buflen) ? 0 : -1;
}

int get_random(unsigned char *buf, u16 len)
{
        return fimport(buf, len, "/dev/urandom");
}

#elif defined(__WIN32__)

#include <windows.h>
#include <wincrypt.h>

int get_random(unsigned char *buf, u16 len)
{
        HCRYPTPROV hCryptProv = 0;

        if (CryptAcquireContext(&hCryptProv, NULL, NULL,
                                PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) == FALSE) {
                return -1;
        }

        if (CryptGenRandom(hCryptProv, len, buf) == FALSE) {
                CryptReleaseContext(hCryptProv, 0);
                return -1;
        }
        CryptReleaseContext(hCryptProv, 0);
        return 0;
}

#else
#error "Unsupported Platform System"
#endif

/*
 * Constant-time buffer comparison algorithm
 */
bool zk_are_equal(const u8 * const buf1, const u8 * const buf2, u16 buflen)
{
  u8 check = 0;
  u16 i;
  for(i=0; i < buflen; ++i){
    check |= (buf1[i] ^ buf2[i]);
  }
  return check == 0;
}


/*
 * Determine if the name of the curve is supported
 */
bool zk_is_supported_curve_name(const char *curve_name, ec_params *ecparams)
{
  const u32 curve_name_len = local_strnlen(curve_name, MAX_CURVE_NAME_LEN) + 1;
  const ec_str_params *tmp = ec_get_curve_params_by_name((u8*)curve_name, curve_name_len);
  if(tmp != NULL)
  {
    if(ecparams != NULL)
    {
      import_params(ecparams, tmp);
    }
    return true;
  }
  return false;
}


/*
 * Determine if the name of the hash is supported
 */
bool zk_is_supported_hash_name(const char *hash_name, const hash_mapping **mapping)
{
  const hash_mapping *tmp = get_hash_by_name(hash_name);
  if(mapping != NULL)
  {
    *mapping = tmp;
  }
  return tmp != NULL;
}

/*
 * Determine if the type of the hash is supported
 */
bool zk_is_supported_hash_type(const hash_alg_type hash_type, const hash_mapping **mapping)
{
  const hash_mapping *tmp = get_hash_by_type(hash_type);
  if(mapping != NULL)
  {
    *mapping = tmp;
  }
  return tmp != NULL;
}
