#ifndef NOKNOW_DISPLAY_H
#define NOKNOW_DISPLAY_H

#include <string.h>
#include <libec.h>
#include <stdio.h>
#include <words/words.h>

#define UNUSED(expr) do { (void)(expr); } while (0)

void zk_display_buf(FILE *stream, const char *label, const u8 *buf, u16 buflen);
void zk_display_prj(FILE *stream, const char *label, prj_pt_src_t p);
void zk_display_aff(FILE *stream, const char *label, aff_pt_src_t p);
void zk_display_nn(FILE *stream, const char *label, nn_src_t);

#endif//NOKNOW_DISPLAY_H
