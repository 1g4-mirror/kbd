/* psffontop.h */

#ifndef _PSFFONTOP_H
#define _PSFFONTOP_H

/* Maximum font size that we try to handle */
#define MAXFONTSIZE 65536

typedef unsigned int unicode;

struct unicode_seq {
	struct unicode_seq *next;
	struct unicode_seq *prev;
	unicode uc;
};

struct unicode_list {
	struct unicode_list *next;
	struct unicode_list *prev;
	struct unicode_seq *seq;
};

extern int readpsffont(FILE *fontf, char **allbufp, size_t *allszp,
                       char **fontbufp, size_t *fontszp,
                       size_t *fontwidthp, size_t *fontlenp, size_t fontpos0,
                       struct unicode_list **uclistheadsp);

extern int writepsffont(FILE *ofil, char *fontbuf,
                        size_t width, size_t height, size_t fontlen, int psftype,
                        struct unicode_list *uclistheads);

#define WPSFH_HASTAB 1
#define WPSFH_HASSEQ 2
extern int writepsffontheader(FILE *ofil,
                              size_t width, size_t height, size_t fontlen,
                              int *psftype, int flags);

extern int appendunicode(FILE *fp, unsigned int uc, int utf8);
extern int appendseparator(FILE *fp, int seq, int utf8);

#endif /* _PSFFONTOP_H */
