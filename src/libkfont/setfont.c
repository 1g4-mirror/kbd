#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

#include "kfont.h"
#include "contextP.h"

#define MAXIFILES 256

static int
_kfont_loadfont(struct kfont_ctx *ctx, char *inbuf, size_t width, size_t height, size_t hwunit,
               size_t fontsize, char *filename)
{
	unsigned char *buf = NULL;
	unsigned int i;
	size_t buflen;
	size_t bytewidth = (width + 7) / 8;
	size_t charsize = height * bytewidth;
	size_t kcharsize = 32 * bytewidth;
	int bad_video_erase_char = 0;

	if (height < 1 || height > 32) {
		ERR(ctx, _("Bad character height %ld"), height);
		return -EX_DATAERR;
	}
	if (width < 1 || width > 32) {
		ERR(ctx, _("Bad character width %ld"), width);
		return -EX_DATAERR;
	}

	if (!hwunit)
		hwunit = height;

	buflen = (size_t)(kcharsize * ((fontsize < 128) ? 128 : fontsize));

	if ((buf = calloc(1, buflen)) == NULL) {
		ERR(ctx, "out of memory");
		return -1;
	}

	for (i = 0; i < fontsize; i++) {
		memcpy(buf + (i * kcharsize), inbuf + (i * charsize), (size_t) charsize);
	}

	/*
	 * Due to a kernel bug, font position 32 is used
	 * to erase the screen, regardless of maps loaded.
	 * So, usually this font position should be blank.
	 */
	for (i = 0; i < kcharsize; i++) {
		if (buf[32 * kcharsize + i])
			bad_video_erase_char = 1;
	}

	if (bad_video_erase_char)
		ERR(ctx, _("font position 32 is nonblank"));

	if (ctx->verbose) {
		if (height == hwunit && filename)
			INFO(ctx, _("Loading %ld-char %ldx%ld font from file %s"), fontsize, width, height, filename);
		else if (height == hwunit)
			INFO(ctx, _("Loading %ld-char %ldx%ld font"), fontsize, width, height);
		else if (filename)
			INFO(ctx, _("Loading %ld-char %ldx%ld (%ld) font from file %s"), fontsize, width, height, hwunit, filename);
		else
			INFO(ctx, _("Loading %ld-char %ldx%ld (%ld) font"), fontsize, width, height, hwunit);
	}

	if (kfont_load_font(ctx, buf, fontsize, width, hwunit)) {
		free(buf);
		return -EX_OSERR;
	}

	free(buf);
	return 0;
}

int __attribute__((format(printf, 4, 5)))
appendf(struct kfont_ctx *ctx, char **buf, size_t *len, const char *fmt, ...)
{
	char *p = NULL;
	size_t msglen = 0;
	ssize_t siz = 0;
	va_list ap;

	va_start(ap, fmt);
	siz = vsnprintf(NULL, 0, fmt, ap);
	va_end(ap);

	if (siz < 0) {
		ERR(ctx, "vsnprintf failed");
		return -1;
	}

	siz++;

	if (*buf)
		msglen = strlen(*buf);

	if ((msglen + (size_t) siz) > *len) {
		if ((p = realloc(*buf, msglen + (size_t) siz)) == NULL) {
			ERR(ctx, "out of memory");
			return -EX_OSERR;
		}
		*buf = p;
		*len = msglen + (size_t) siz;
	}

	va_start(ap, fmt);
	siz = vsnprintf(*buf + msglen, (size_t) siz, fmt, ap);
	va_end(ap);

	return 0;
}

static int
do_loadtable(struct kfont_ctx *ctx, struct unicode_list *uclistheads, size_t fontsize)
{
	struct unimapdesc ud;
	struct unipair *up;
	unsigned int i, ct = 0, maxct;
	struct unicode_list *ul;
	struct unicode_seq *us;

	int rc = 0;
	char *buf = NULL;
	size_t buflen = 0;

	maxct = 0;
	for (i = 0; i < fontsize; i++) {
		ul = uclistheads[i].next;
		while (ul) {
			us = ul->seq;
			if (us && !us->next)
				maxct++;
			ul = ul->next;
		}
	}

	if ((up = malloc(maxct * sizeof(struct unipair))) == NULL) {
		ERR(ctx, "out of memory");
		return -EX_OSERR;
	}

	for (i = 0; i < fontsize; i++) {
		ul = uclistheads[i].next;

		if (ctx->verbose > 1) {
			if ((rc = appendf(ctx, &buf, &buflen, "char %03x:", i)) < 0)
				goto end;
		}

		while (ul) {
			us = ul->seq;

			if (us && !us->next) {
				up[ct].unicode = us->uc;
				up[ct].fontpos = i;
				ct++;

				if (ctx->verbose > 1) {
					if ((rc = appendf(ctx, &buf, &buflen, " %04x", us->uc)) < 0)
						goto end;
				}
			} else if (ctx->verbose > 1) {
				if ((rc = appendf(ctx, &buf, &buflen, " seq: <")) < 0)
					goto end;

				while (us) {
					if ((rc = appendf(ctx, &buf, &buflen, " %04x", us->uc)) < 0)
						goto end;
					us = us->next;
				}

				if ((rc = appendf(ctx, &buf, &buflen, " >")) < 0)
					goto end;
			}

			if (ctx->verbose > 1) {
				if ((rc = appendf(ctx, &buf, &buflen, ",")) < 0)
					goto end;
			}

			ul = ul->next;
		}

		if (buf && buf[0] != '\0') {
			INFO(ctx, "%s", buf);
			memset(buf, 0, buflen);
		}
	}

	if (buf) {
		free(buf);
		buf = NULL;
	}

	if (ct != maxct) {
		free(up);
		ERR(ctx, _("bug in do_loadtable"));
		return -EX_SOFTWARE;
	}

	if (ctx->verbose)
		INFO(ctx, _("Loading Unicode mapping table..."));

	ud.entry_ct = ct;
	ud.entries  = up;

	if (kfont_load_unimap(ctx, NULL, &ud)) {
		free(up);
		return -EX_OSERR;
	}
end:
	if (up)
		free(up);
	if (buf)
		free(buf);

	return rc;
}

static ssize_t
position_codepage(struct kfont_ctx *ctx, size_t iunit)
{
	int offset;

	/*
	 * code page: first 40 bytes, then 8x16 font,
	 * then 6 bytes, then 8x14 font,
	 * then 6 bytes, then 8x8 font
	 */

	if (!iunit) {
		ERR(ctx, _("This file contains 3 fonts: 8x8, 8x14 and 8x16. "
		           "Please indicate using an option -8 or -14 or -16 "
		           "which one you want loaded."));
		return -EX_USAGE;
	}

	switch (iunit) {
		case 8:
			offset = 7732;
			break;
		case 14:
			offset = 4142;
			break;
		case 16:
			offset = 40;
			break;
		default:
			ERR(ctx, _("You asked for font size %ld, "
			           "but only 8, 14, 16 are possible here."),
			        iunit);
			return -EX_USAGE;
	}

	return offset;
}

static const char *combineheader = "# combine partial fonts\n";

static int
load_combine_fonts(struct kfont_ctx *ctx, char *inbuf, size_t inlen, size_t iunit, size_t hwunit)
{
	char *p, *q;
	char *ifiles[MAXIFILES];
	int ifilct = 0;
	int rc = 0;
	size_t chlth = strlen(combineheader);

	if (inlen < chlth || strncmp(inbuf, combineheader, chlth))
		return 0;

	q = inbuf + chlth;

	while (q < inbuf + inlen) {
		p = q;

		while (q < inbuf + inlen && *q != '\n')
			q++;

		if (q == inbuf + inlen) {
			ERR(ctx, _("No final newline in combine file"));
			return -EX_DATAERR;
		}

		*q++ = 0;

		if (ifilct == MAXIFILES) {
			ERR(ctx, _("Too many files to combine"));
			return -EX_DATAERR;
		}

		ifiles[ifilct++] = p;
	}

	rc = kfont_load_fonts(ctx, ifiles, ifilct, iunit, hwunit);
	if (rc < 0)
		return rc;

	return 1;
}

static int
loadnewfont(struct kfont_ctx *ctx, char *ifil, size_t iunit, size_t hwunit)
{
	struct kbdfile *fp = NULL;
	struct kbdfile_ctx *kbdfile_ctx = NULL;

	size_t height = 0, width = 8, bytewidth = 0;
	int rc = 0, def = 0;
	char *inbuf = NULL, *fontbuf = NULL;
	size_t inputlth = 0, fontbuflth = 0, fontsize = 0, offset = 0;
	struct unicode_list *uclistheads = NULL;

	if ((kbdfile_ctx = kbdfile_context_new()) == NULL) {
		ERR(ctx, "out of memory");
		rc = -EX_OSERR;
		goto end;
	}

	if ((fp = kbdfile_new(kbdfile_ctx)) == NULL) {
		ERR(ctx, "out of memory");
		rc = -EX_OSERR;
		goto end;
	}

	if (!*ifil) {
		/* try to find some default file */

		def = 1; /* maybe also load default unimap */

		if (iunit > 32)
			iunit = 0;

		if (iunit == 0) {
			if (kbdfile_find(ifil = (char *) "default",     ctx->fontdirs, ctx->fontsuffixes, fp) &&
			    kbdfile_find(ifil = (char *) "default8x16", ctx->fontdirs, ctx->fontsuffixes, fp) &&
			    kbdfile_find(ifil = (char *) "default8x14", ctx->fontdirs, ctx->fontsuffixes, fp) &&
			    kbdfile_find(ifil = (char *) "default8x8",  ctx->fontdirs, ctx->fontsuffixes, fp)) {
				ERR(ctx, _("Cannot find default font"));
				rc = -EX_NOINPUT;
				goto end;
			}
		} else {
			char defname[20];

			snprintf(defname, sizeof(defname), "default8x%ld", iunit);

			if (kbdfile_find(ifil = defname, ctx->fontdirs, ctx->fontsuffixes, fp) &&
			    kbdfile_find(ifil = (char *) "default", ctx->fontdirs, ctx->fontsuffixes, fp)) {
				ERR(ctx, _("Cannot find %s font"), ifil);
				rc = -EX_NOINPUT;
				goto end;
			}
		}
	} else {
		if (kbdfile_find(ifil, ctx->fontdirs, ctx->fontsuffixes, fp)) {
			ERR(ctx, _("Cannot open font file %s"), ifil);
			rc = -EX_NOINPUT;
			goto end;
		}
	}

	if (ctx->verbose > 1)
		INFO(ctx, _("Reading font file %s"), ifil);

	rc = kfont_read_file(ctx, kbdfile_get_file(fp), &inbuf, &inputlth);
	if (rc < 0)
		goto end;

	rc = kfont_read_psffont(ctx, inbuf, inputlth, &fontbuf, &fontbuflth, &width, &fontsize, 0,
		(ctx->flags & KFONT_FLAG_SKIP_LOAD_UNICODE_MAP) ? NULL : &uclistheads);

	if (!rc) {
		/* we've got a psf font */
		bytewidth = (width + 7) / 8;
		height    = fontbuflth / (bytewidth * fontsize);

		rc = _kfont_loadfont(ctx, fontbuf, width, height, hwunit, fontsize, kbdfile_get_pathname(fp));

		if (rc < 0)
			goto end;

		if (uclistheads && !(ctx->flags & KFONT_FLAG_SKIP_LOAD_UNICODE_MAP)) {
			rc = do_loadtable(ctx, uclistheads, fontsize);
			if (rc < 0)
				goto end;
		}

		if (!uclistheads && !(ctx->flags & KFONT_FLAG_SKIP_LOAD_UNICODE_MAP) && def) {
			rc = kfont_load_unicodemap(ctx, "def.uni");
		}

		goto end;
	} else if (rc == 1) {
		/* instructions to combine fonts? */
		rc = load_combine_fonts(ctx, inbuf, inputlth, iunit, hwunit);
		if (rc < 0 || rc == 1)
			goto end;
	} else {
		goto end;
	}

	/* file with three code pages? */
	if (inputlth == 9780) {
		ssize_t ret = position_codepage(ctx, iunit);
		if (ret < 0) {
			rc = (int) ret;
			goto end;
		}

		offset   = (size_t) ret;
		height   = iunit;
		fontsize = 256;
		width    = 8;
	} else if (inputlth == 32768) {
		/* restorefont -w writes a SVGA font to file
		   restorefont -r restores it
		   These fonts have size 32768, for two 512-char fonts.
		   In fact, when BROKEN_GRAPHICS_PROGRAMS is defined,
		   and it always is, there is no default font that is saved,
		   so probably the second half is always garbage. */
		ERR(ctx, _("Hmm - a font from restorefont? Using the first half"));
		inputlth = 16384; /* ignore rest */
		fontsize = 512;
		offset   = 0;
		width    = 8;
		height   = 32;
		if (!hwunit)
			hwunit = 16;
	} else {
		size_t rem = (inputlth % 256);
		if (rem == 0 || rem == 40) {
			/* 0: bare code page bitmap */
			/* 40: preceded by .cp header */
			/* we might check some header details */
			offset = rem;
		} else {
			ERR(ctx, _("Bad input file size: %s"), ifil);
			rc = -EX_DATAERR;
			goto end;
		}
		fontsize = 256;
		width    = 8;
		height   = inputlth / 256;
	}

	rc = _kfont_loadfont(ctx, inbuf + offset, width, height, hwunit, fontsize, kbdfile_get_pathname(fp));

end:
	kbdfile_free(fp);
	kbdfile_context_free(kbdfile_ctx);
	unicode_list_free(&uclistheads, fontsize);
	free(inbuf);

	return rc;
}

int
kfont_load_fonts(struct kfont_ctx *ctx, char **ifiles, int ifilct, size_t iunit, size_t hwunit)
{
	void *ptr = NULL;
	char *ifil = NULL, *inbuf = NULL, *fontbuf = NULL, *bigfontbuf = NULL;
	size_t inputlth = 0, fontbuflth = 0, fontsize = 0, height = 0, width = 0, bytewidth = 0;
	size_t bigfontbuflth = 0, bigfontsize = 0, bigheight = 0, bigwidth = 0;
	struct unicode_list *uclistheads = NULL;
	int i, rc = 0;
	struct kbdfile *fp = NULL;
	struct kbdfile_ctx *kbdfile_ctx = NULL;

	if (ifilct == 1)
		return loadnewfont(ctx, ifiles[0], iunit, hwunit);

	if ((kbdfile_ctx = kbdfile_context_new()) == NULL) {
		ERR(ctx, "out of memory");
		return -EX_OSERR;
	}

	/* several fonts that must be merged */
	/* We just concatenate the bitmaps - only allow psf fonts */
	for (i = 0; i < ifilct; i++) {
		if ((fp = kbdfile_new(kbdfile_ctx)) == NULL) {
			ERR(ctx, "out of memory");
			rc = -EX_OSERR;
			goto end;
		}

		ifil = ifiles[i];

		if (kbdfile_find(ifil, ctx->fontdirs, ctx->fontsuffixes, fp) &&
		    kbdfile_find(ifil, ctx->partfontdirs, ctx->partfontsuffixes, fp)) {
			ERR(ctx, _("Cannot open font file %s"), ifil);
			rc = -EX_NOINPUT;
			break;
		}

		fontbuf = NULL;
		inputlth = fontbuflth = 0;
		fontsize = 0;

		rc = kfont_read_file(ctx, kbdfile_get_file(fp), &inbuf, &inputlth);
		if (rc < 0)
			break;

		rc = kfont_read_psffont(ctx, inbuf, inputlth, &fontbuf, &fontbuflth, &width, &fontsize, bigfontsize,
			(ctx->flags & KFONT_FLAG_SKIP_LOAD_UNICODE_MAP) ? NULL : &uclistheads);

		if (rc < 0) {
			ERR(ctx, _("When loading several fonts, all must be psf fonts - %s isn't"), kbdfile_get_pathname(fp));
			rc = -EX_DATAERR;
			break;
		}

		bytewidth = (width + 7) / 8;
		height    = fontbuflth / (bytewidth * fontsize);

		if (ctx->verbose)
			INFO(ctx, _("Read %ld-char %ldx%ld font from file %s"), fontsize, width, height, kbdfile_get_pathname(fp));

		fp = kbdfile_free(fp); // avoid zombies, jw@suse.de (#88501)
		kbdfile_ctx = kbdfile_context_free(kbdfile_ctx);

		if (bigheight == 0)
			bigheight = height;
		else if (bigheight != height) {
			ERR(ctx, _("When loading several fonts, all must have the same height"));
			rc = -EX_DATAERR;
			break;
		}

		if (bigwidth == 0)
			bigwidth = width;
		else if (bigwidth != width) {
			ERR(ctx, _("When loading several fonts, all must have the same width"));
			rc = -EX_DATAERR;
			break;
		}

		bigfontsize += fontsize;
		bigfontbuflth += fontbuflth;

		if ((ptr = realloc(bigfontbuf, bigfontbuflth)) == NULL) {
			ERR(ctx, "out of memory");
			rc = -EX_OSERR;
			break;
		}
		bigfontbuf = ptr;

		memcpy(bigfontbuf + bigfontbuflth - fontbuflth, fontbuf, fontbuflth);

		free(inbuf);
		inbuf = NULL;
	}

	if (rc == 0)
		rc = _kfont_loadfont(ctx, bigfontbuf, bigwidth, bigheight, hwunit, bigfontsize, NULL);

	if (rc == 0 && uclistheads && !(ctx->flags & KFONT_FLAG_SKIP_LOAD_UNICODE_MAP))
		rc = do_loadtable(ctx, uclistheads, bigfontsize);

end:
	kbdfile_free(fp);
	kbdfile_context_free(kbdfile_ctx);
	unicode_list_free(&uclistheads, bigfontsize);

	free(inbuf);
	free(bigfontbuf);

	return rc;
}
