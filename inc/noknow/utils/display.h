#ifndef NOKNOW_DISPLAY_H
#define NOKNOW_DISPLAY_H

#include <mbedtls/ecp.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#define UNUSED(expr) do { (void)(expr); } while (0)
void zk_display_buf(FILE *stream, const char *label, const uint8_t *buf, size_t buflen);
void zk_display_mpi(FILE *stream, const char *label, const mbedtls_mpi *mpi);
void zk_display_point(FILE *stream, const char *label, const mbedtls_ecp_group *curve, const mbedtls_ecp_point *pt);

#if 0
void zk_display_buf(FILE *stream, const char *label, const u8 *buf, u16 buflen);
void zk_display_prj(FILE *stream, const char *label, prj_pt_src_t p);
void zk_display_aff(FILE *stream, const char *label, aff_pt_src_t p);
void zk_display_nn(FILE *stream, const char *label, nn_src_t);
#endif

#endif//NOKNOW_DISPLAY_H
