#include <noknow/utils/display.h>
#include <noknow/debug.h>

/*
 * Used for simply displaying various objects used throughout NoKnow in a friendly way
 * Primarily used for debugging purposes
 */

static inline void showhex(FILE *stream, const uint8_t * const buf, size_t len) {
  for(size_t i = 0; i < len; ++i) { fprintf(stream, "%02x", buf[i]); }
  fputc('\n', stream);
}

void zk_display_buf(FILE *stream, const char *label, const uint8_t *buf, size_t buflen) {
  fprintf(stream, "  %s:\n  ", label);
  showhex(stream, buf, buflen);
}

void zk_display_mpi(FILE *stream, const char *label, const mbedtls_mpi *mpi) {
  uint8_t buf[MBEDTLS_ECP_MAX_BYTES << 2];
  size_t len = mbedtls_mpi_size(mpi);
  mbedtls_mpi_write_binary(mpi, buf, len);
  fputs("  ", stream);
  fputs(label, stream);
  fputs(": ", stream);
  showhex(stream, buf, len);
}

void zk_display_point(FILE *stream, const char *label, const mbedtls_ecp_group *curve, const mbedtls_ecp_point *pt) {
  fprintf(stream, "  %s:\n", label);
  uint8_t buf[MBEDTLS_ECP_MAX_BYTES];
  size_t len = mbedtls_mpi_size(&curve->P);

  mbedtls_mpi_write_binary(&pt->X, buf, len);
  fputs("    X: ", stream);
  showhex(stream, buf, len);
  memset(buf, 0, len);

  mbedtls_mpi_write_binary(&pt->Y, buf, len);
  fputs("    Y: ", stream);
  showhex(stream, buf, len);
  memset(buf, 0, len);
}