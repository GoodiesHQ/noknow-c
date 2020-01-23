#include <noknow/utils/display.h>

/*
 * Used for simply displaying various objects used throughout NoKnow in a friendly way
 * Primarily used for debugging purposes
 */

void showhex(FILE *stream, const u8 * const buf, u16 len)
{
  u16 i;
  for(i = 0; i < len; ++i)
  {
    //fprintf(stdout, " i: %i ~ %u\n", i, len);
    fprintf(stream, "%02x", buf[i]);
  }
  fputc('\n', stream);
}

void zk_display_aff(FILE *stream, const char *label, aff_pt_src_t p) {
  if(!aff_pt_is_initialized(p)) { return; }
  u16 buflen;
  u8 buf[BYTECEIL(CURVES_MAX_P_BIT_LEN) * 2] = { 0 };

  buflen = BYTECEIL(p->x.ctx->p_bitlen);
  fp_export_to_buf(buf, buflen, &p->x);
  fprintf(stream, "  %s:\n", label);
  fputs("    X: ", stream);
  showhex(stream, buf, buflen);
  memset(buf, 0, buflen);

  buflen = BYTECEIL(p->y.ctx->p_bitlen);
  fp_export_to_buf(buf, buflen, &p->y);
  fputs("    Y: ", stream);
  showhex(stream, buf, buflen);
  memset(buf, 0, buflen);
}

void zk_display_prj(FILE *stream, const char *label, prj_pt_src_t p)
{
  aff_pt ap;
  prj_pt_to_aff(&ap, p);
  zk_display_aff(stream, label, &ap);
  aff_pt_uninit(&ap);
}


void zk_display_buf(FILE *stream, const char *label, const u8 *buf, u16 buflen)
{
  fprintf(stream, "  %s:\n  ", label);
  showhex(stream, buf, buflen);
}

void zk_display_nn(FILE *stream, const char *label, nn_src_t n)
{
  const u16 buflen = (n->wlen * WORD_BYTES);
  u8 buf[BYTE_LEN_WORDS(NN_MAX_BIT_LEN) << 1];
  fprintf(stream, "  %s: ", label);
  if(buflen == 0){
    fputs("0\n", stream);
  }
  nn_export_to_buf(buf, buflen, n);
  showhex(stream, buf, buflen);
  memset(buf, 0, buflen);
}
