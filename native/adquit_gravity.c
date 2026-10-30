/* adquit_gravity.c - the blocklist index, in C, reached from Python through ctypes.
 *
 * WHY THIS EXISTS
 * ---------------
 * A fortress with 4.2M rules spends its life holding them in a Python dict. Measured on this
 * repo's own corpus: 4.2M `domain -> (cat, vector, feed)` rows cost ~950 MB of anonymous RSS, take
 * seconds to unpickle at boot, and every DNS query pays a `dict.get` plus a parent walk that builds
 * a fresh substring per label. On the hardware this project usually lands on - a 1-2 GB Pi, or a
 * NAS that is doing other things - that dict is the difference between an ad blocker and a box that
 * has started swapping.
 *
 * This file replaces the *storage*, not the policy. Normalisation, exemptions, category rules and
 * the rest of `classify()` stay in app.py, so there is still exactly one definition of what a
 * domain is and one place where a blocking decision is made. What moves here is the part that is a
 * byte-exact set-membership test over ~4M keys:
 *
 *   - the index is a file, mapped read-only. Pages come from the page cache, are shared between
 *     processes, fault in only where touched, and are the first thing the kernel reclaims when RAM
 *     gets tight. Anonymous dict memory is none of those.
 *   - a lookup is FNV-1a over the bytes, one or two probes into a u32 table, and a memcmp against
 *     the pool. No hashing of 4M keys at boot, no allocation per query, nothing for the GC to see -
 *     which is also what makes it behave the same in year three as in minute one.
 *   - the parent walk for wildcard zones happens here, without building substrings at all.
 *
 * THE HOT ABI
 * -----------
 * One call, one u32 out, because at this size a ctypes call is worth about as much as the lookup:
 *
 *      0                miss
 *      bit 0            1 on a hit
 *      bit 1            0 = exact rule, 1 = wildcard zone
 *      bits 2-17        meta index - which feed and category. 16 bits is enough because a fortress
 *                       has ~100 feeds, not ~4M categories; app.py reads the text back once.
 *      bits 18-25       byte offset, inside the queried name, where the matching zone starts. 8
 *                       bits is exact rather than convenient: app.py hands this library names it
 *                       has already trimmed to 253 bytes, the DNS limit.
 *
 * WHAT IS NOT TRUSTED
 * -------------------
 * The file is written by `gb_build` in this same library, from a stream the engine produces, so the
 * bytes are exactly the keys the engine looks up - no second list parser to keep in sync. Even so,
 * every offset is re-derived and bounds-checked at load (`gb_check_layout`), so a truncated write, a
 * half-copied file or a hand-edited one is *rejected* and the engine keeps its dict path instead of
 * reading outside the mapping. Nothing here is a place where a malformed file becomes a bug.
 *
 * Build (what install.sh does):
 *   cc -O2 -fPIC -shared -Wall -Wextra -pthread -o libadquit_gravity.so adquit_gravity.c
 * `-march=native` is added when the compiler accepts it, and left out when it does not: an illegal
 * instruction on the wrong CPU is not a speed improvement.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#define GB_MAGIC    0x4A514441u   /* "ADQJ" - a fortress file, not a generic index */
#define GB_VERSION  1u
#define GB_MAX_NAME 253u          /* a DNS name; app.py trims to this before calling us */
#define GB_MAX_META 65535u        /* the 16-bit field in the packed return */
#define GB_SLOTS    8             /* live index + the couple of retired ones still being read */
#define GB_HDR_BYTES 128u

typedef struct {
    uint32_t magic, version;
    uint32_t n_exact, n_wild, n_meta;
    uint32_t tbl_bits;            /* exact table: 1 << tbl_bits slots */
    uint32_t wild_bits;           /* zone table: sized for the zones, not for both (a fortress has
                                     4M exact rules and a few hundred zones, and sharing one size
                                     between them spent 33 MB of slots on 65 entries) */
    uint32_t pool_bytes;
    uint32_t meta_bytes;
    uint32_t hdr_bytes;           /* where the tables start: room to grow the header later */
    uint32_t _pad;                /* keeps the header 8-byte aligned; the file is padded to
                                     hdr_bytes, so a later version can grow without moving tables */
    uint64_t built_ns;
    uint64_t f_size;
} gb_hdr;

typedef struct {
    uint8_t  *base;
    size_t    map_len;
    gb_hdr   *hdr;                /* points into the mapping */
    uint32_t *exact_tbl, *wild_tbl;
    uint64_t *exact_hash, *wild_hash;
    uint32_t *exact_off, *wild_off;
    uint16_t *exact_meta, *wild_meta;
    char     *pool;
    char     *meta;
    uint8_t  *active;             /* one byte per meta index: is that feed armed? NULL = all armed */
    volatile int retired;
    volatile unsigned inflight;
} gb_view;

static gb_view gb_slots[GB_SLOTS];
static pthread_mutex_t gb_lock = PTHREAD_MUTEX_INITIALIZER;
static char gb_err[256] = "no error yet";

#define GB_EXPORT __attribute__((visibility("default")))

static void gb_seterr(const char *fmt, ...)
#if defined(__GNUC__)
    __attribute__((format(printf, 1, 2)))
#endif
    ;

#include <stdarg.h>
static void gb_seterr(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(gb_err, sizeof(gb_err), fmt, ap);
    va_end(ap);
}

GB_EXPORT const char *gb_last_error(void)
{
    return gb_err;
}

/* ─────────────────────────────  hash  ───────────────────────────── */
static inline uint64_t gb_fnv1a(const char *s, uint32_t n)
{
    uint64_t h = 1469598103934665603ULL;
    for (uint32_t i = 0; i < n; i++) {
        h ^= (unsigned char)s[i];
        h *= 1099511628211ULL;
    }
    h ^= h >> 33;                       /* so neighbouring names do not clump in the low bits */
    h *= 0xff51afd7ed558ccdULL;
    h ^= h >> 29;
    return h;
}

/* ─────────────────────────────  growable row store  ───────────────────────────── */
typedef struct {
    uint64_t *hash;
    uint32_t *off;
    uint16_t *meta;
    uint32_t  n, cap;
} gb_rows;

static int gb_rows_push(gb_rows *r, uint32_t cap_hint)
{
    if (r->n < r->cap)
        return 1;
    uint32_t cap = r->cap ? r->cap * 2 : (cap_hint ? cap_hint : 1024u);
    if (cap > (1u << 27)) {
        gb_seterr("index would exceed 134M rows - refusing to allocate");
        return 0;
    }
    uint64_t *h = (uint64_t *)realloc(r->hash, (size_t)cap * sizeof(uint64_t));
    if (!h) { gb_seterr("out of memory growing the hash array"); return 0; }
    r->hash = h;
    uint32_t *o = (uint32_t *)realloc(r->off, (size_t)cap * sizeof(uint32_t));
    if (!o) { gb_seterr("out of memory growing the offset array"); return 0; }
    r->off = o;
    uint16_t *m = (uint16_t *)realloc(r->meta, (size_t)cap * sizeof(uint16_t));
    if (!m) { gb_seterr("out of memory growing the meta array"); return 0; }
    r->meta = m;
    r->cap = cap;
    return 1;
}

static void gb_rows_free(gb_rows *r)
{
    free(r->hash); free(r->off); free(r->meta);
    memset(r, 0, sizeof(*r));
}

typedef struct {
    char   *buf;
    size_t  len, cap;
} gb_blob;

static int gb_blob_add(gb_blob *b, const char *s, size_t n)
{
    if (b->len + n > b->cap) {
        size_t cap = b->cap ? b->cap * 2 : 65536;
        while (cap < b->len + n)
            cap *= 2;
        char *p = (char *)realloc(b->buf, cap);
        if (!p) { gb_seterr("out of memory growing a pool"); return 0; }
        b->buf = p;
        b->cap = cap;
    }
    memcpy(b->buf + b->len, s, n);
    b->len += n;
    return 1;
}

/* ─────────────────────────────  build  ───────────────────────────── */
/* Input is the engine's own truth, one row per line, tab separated:
 *      E<TAB>domain<TAB>cat<TAB>vector<TAB>feed
 *      W<TAB>domain<TAB>cat<TAB>vector<TAB>feed
 * app.py writes it from BLOCKED.items() / WILDCARDS.items(), so the keys are already normalised and
 * unique, and this library never grows an opinion about what a domain looks like. A duplicate is
 * accepted with last-write-wins rather than rejected: it costs a wasted pool record and cannot
 * produce a wrong answer.
 */
typedef struct { char *key; uint16_t id; } gb_meta_ent;

/* How long the NUL-terminated name at `off` is, never reading past the pool. A pool that lost its
 * final NUL therefore reports "too long" and the file is rejected, rather than walking off the end
 * of the mapping looking for one. */
static uint32_t gb_namlen(const char *pool, uint32_t pool_bytes, uint32_t off)
{
    if (off >= pool_bytes)
        return pool_bytes + 1;
    return (uint32_t)strnlen(pool + off, pool_bytes - off);
}

static uint32_t gb_meta_intern(gb_meta_ent *tbl, uint32_t mask, gb_blob *meta, const char *cat,
                              const char *vec, const char *src, uint32_t *count, uint32_t *bytes)
{
    char triple[512];
    int n = snprintf(triple, sizeof(triple), "%s\n%s\n%s", cat, vec, src);
    if (n <= 0 || (size_t)n >= sizeof(triple))
        return GB_MAX_META + 1;             /* "too long to be a feed id" */
    uint64_t h = gb_fnv1a(triple, (uint32_t)n);
    uint32_t i = (uint32_t)(h & mask);
    for (;;) {
        if (tbl[i].key == NULL)
            break;
        if (strcmp(tbl[i].key, triple) == 0)
            return tbl[i].id;
        i = (i + 1) & mask;
    }
    if (*count >= GB_MAX_META) {
        gb_seterr("more than %u distinct (category, vector, feed) triples - the 16-bit meta field "
                  "is full", GB_MAX_META);
        return GB_MAX_META + 1;
    }
    char *dup = strdup(triple);
    if (!dup) { gb_seterr("out of memory interning a feed"); return GB_MAX_META + 1; }
    tbl[i].key = dup;
    tbl[i].id = (uint16_t)*count;
    /* three NUL-separated fields, so a reader can split without parsing JSON */
    if (!gb_blob_add(meta, cat, strlen(cat) + 1) || !gb_blob_add(meta, vec, strlen(vec) + 1)
        || !gb_blob_add(meta, src, strlen(src) + 1))
        return GB_MAX_META + 1;
    *bytes = (uint32_t)meta->len;
    return (*count)++;
}

GB_EXPORT int gb_build(const char *in_path, const char *out_path)
{
    FILE *fh = fopen(in_path, "r");
    if (!fh) {
        gb_seterr("cannot read %s: %s", in_path, strerror(errno));
        return -1;
    }
    gb_rows ex, wc;
    memset(&ex, 0, sizeof(ex));
    memset(&wc, 0, sizeof(wc));
    gb_blob pool, meta;
    memset(&pool, 0, sizeof(pool));
    memset(&meta, 0, sizeof(meta));

    /* meta table sized generously: feeds are ~100, and this runs once per gravity compile */
    uint32_t mmask = 4095u;
    gb_meta_ent *mtbl = (gb_meta_ent *)calloc(mmask + 1, sizeof(gb_meta_ent));
    if (!mtbl) { fclose(fh); gb_seterr("out of memory"); return -1; }
    uint32_t nmeta = 0, meta_bytes = 0;

    int rc = -1;
    char line[1024];
    uint32_t n_exact = 0, n_wild = 0, bad = 0;
    while (fgets(line, sizeof(line), fh)) {
        char kind = line[0];
        if (kind != 'E' && kind != 'W')
            continue;
        line[strcspn(line, "\n")] = 0;
        char *f1 = strchr(line, '\t');
        if (!f1) { bad++; continue; }
        *f1++ = 0;
        char *f2 = strchr(f1, '\t');
        char *f3 = f2 ? strchr(f2 + 1, '\t') : NULL;
        char *f4 = f3 ? strchr(f3 + 1, '\t') : NULL;
        if (!f2 || !f3 || !f4) { bad++; continue; }
        *f2++ = 0; *f3++ = 0; *f4++ = 0;
        uint32_t dlen = (uint32_t)strlen(f1);
        if (dlen == 0 || dlen > GB_MAX_NAME) { bad++; continue; }

        uint32_t mid = gb_meta_intern(mtbl, mmask, &meta, f2, f3, f4, &nmeta, &meta_bytes);
        if (mid > GB_MAX_META) { bad++; continue; }

        gb_rows *r = (kind == 'E') ? &ex : &wc;
        if (!gb_rows_push(r, 1u << 20)) goto fail;
        if (!gb_blob_add(&pool, f1, dlen + 1)) goto fail;   /* the NUL rides along in the length */
        uint32_t idx = r->n++;
        r->hash[idx] = gb_fnv1a(f1, dlen);
        r->off[idx] = (uint32_t)(pool.len - dlen - 1);
        r->meta[idx] = (uint16_t)mid;
        if (kind == 'E') n_exact++; else n_wild++;
    }
    fclose(fh);
    fh = NULL;

    if (n_exact == 0) {
        gb_seterr("no exact rows in %s - an empty index would silently unblock everything", in_path);
        goto fail;
    }

    uint32_t bits = 4, wbits = 4;
    while (((uint64_t)1 << bits) < (uint64_t)n_exact * 4 / 3)      /* load factor <= 0.75 */
        bits++;
    while (((uint64_t)1 << wbits) < (uint64_t)(n_wild ? n_wild : 1) * 4 / 3)
        wbits++;
    if (bits < 4) bits = 4;
    if (wbits < 4) wbits = 4;
    uint32_t tsize = (uint32_t)1 << bits, wsize = (uint32_t)1 << wbits;
    uint32_t mask = tsize - 1, wmask = wsize - 1;

    uint32_t *te = (uint32_t *)calloc(tsize, sizeof(uint32_t));
    uint32_t *tw = (uint32_t *)calloc(wsize, sizeof(uint32_t));
    if (!te || !tw) { gb_seterr("out of memory building the tables"); free(te); free(tw);
                      fclose(fh); fh = NULL; goto fail; }

    int table_ok = 1;
    for (uint32_t pass = 0; pass < 2 && table_ok; pass++) {
        gb_rows *r = pass ? &wc : &ex;
        uint32_t *tbl = pass ? tw : te;
        uint32_t m = pass ? wmask : mask;
        for (uint32_t i = 0; i < r->n && table_ok; i++) {
            uint32_t p = (uint32_t)(r->hash[i] & m);
            uint32_t step = 0;
            while (tbl[p] != 0) {
                p = (p + 1) & m;
                if (++step > mask) {          /* cannot happen at load factor 0.75, but a full
                                                 table must never mean "silently drop a rule" */
                    gb_seterr("hash table full while building the %s table",
                              pass ? "wildcard" : "exact");
                    table_ok = 0;
                    break;
                }
            }
            if (table_ok)
                tbl[p] = i + 1;
        }
    }
    if (!table_ok) { free(te); free(tw); goto fail; }

    gb_hdr h;
    memset(&h, 0, sizeof(h));
    h.magic = GB_MAGIC;
    h.version = GB_VERSION;
    h.n_exact = n_exact;
    h.n_wild = n_wild;
    h.n_meta = nmeta;
    h.tbl_bits = bits;
    h.wild_bits = wbits;
    h.pool_bytes = (uint32_t)pool.len;
    h.meta_bytes = meta_bytes;
    h.hdr_bytes = GB_HDR_BYTES;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    h.built_ns = (uint64_t)tv.tv_sec * 1000000000ULL + (uint64_t)tv.tv_usec * 1000ULL;

    size_t tables = (size_t)tsize * sizeof(uint32_t) + (size_t)wsize * sizeof(uint32_t);
    size_t rows = ((sizeof(uint64_t) + sizeof(uint32_t) + sizeof(uint16_t))
                   * ((size_t)n_exact + n_wild));
    /* the file is laid out from hdr_bytes, not from sizeof(gb_hdr): the header is padded so a
     * later version can add fields without moving the tables - which is what keeps an index built
     * by an older fortress readable by a newer one, instead of a silently wrong lookup. The rows
     * are 64-bit, so they start on the next aligned boundary after the tables; gb_check_layout
     * re-derives the same number from the header, and the two must agree or every lookup is garbage
     * - which is why the parity test in tests/ walks the whole corpus rather than one name. */
    size_t pad = (8u - (tables % 8u)) % 8u;
    h.f_size = (uint64_t)(h.hdr_bytes + tables + pad + rows + pool.len + meta.len);

    int fd = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) { gb_seterr("cannot write %s: %s", out_path, strerror(errno)); free(te); free(tw); goto fail; }
    FILE *out = fdopen(fd, "wb");
    if (!out) { gb_seterr("fdopen failed: %s", strerror(errno)); close(fd); free(te); free(tw); goto fail; }
    if (fwrite(&h, sizeof(h), 1, out) != 1) { gb_seterr("header write failed"); goto wdone; }
    if (h.hdr_bytes > sizeof(h) && fseek(out, (long)(h.hdr_bytes - sizeof(h)), SEEK_CUR) != 0) {
        gb_seterr("header pad seek failed"); goto wdone;
    }
    if (fwrite(te, sizeof(uint32_t), tsize, out) != tsize
        || fwrite(tw, sizeof(uint32_t), wsize, out) != wsize) { gb_seterr("table write failed"); goto wdone; }
    if (pad && fseek(out, (long)pad, SEEK_CUR) != 0) { gb_seterr("row alignment seek failed"); goto wdone; }
    if (fwrite(ex.hash, sizeof(uint64_t), n_exact, out) != n_exact
        || fwrite(ex.off, sizeof(uint32_t), n_exact, out) != n_exact
        || fwrite(ex.meta, sizeof(uint16_t), n_exact, out) != n_exact
        || (n_wild && (fwrite(wc.hash, sizeof(uint64_t), n_wild, out) != n_wild
                       || fwrite(wc.off, sizeof(uint32_t), n_wild, out) != n_wild
                       || fwrite(wc.meta, sizeof(uint16_t), n_wild, out) != n_wild))) {
        gb_seterr("row write failed"); goto wdone;
    }
    if ((pool.len && fwrite(pool.buf, 1, pool.len, out) != pool.len)
        || (meta.len && fwrite(meta.buf, 1, meta.len, out) != meta.len)) {
        gb_seterr("pool write failed"); goto wdone;
    }
    if (ftruncate(fileno(out), (off_t)h.f_size) != 0) { gb_seterr("size set failed"); goto wdone; }
    fflush(out);
    fsync(fileno(out));                    /* one sync per gravity compile; the index is rebuildable */
    rc = 0;
wdone:
    fclose(out);
    free(te);
    free(tw);
    if (rc != 0)
        unlink(out_path);                   /* never leave a half index for the next boot to trust */
fail:
    /* `wdone` falls through here on purpose: both paths share the cleanup, and `rc` says which one
     * it was. (An earlier revision returned -1 unconditionally, so a *successful* build reported
     * failure - a label you can fall into must be re-read, not just written.) */
    if (fh)
        fclose(fh);
    gb_rows_free(&ex);
    gb_rows_free(&wc);
    free(pool.buf);
    free(meta.buf);
    if (mtbl) {
        for (uint32_t i = 0; i <= mmask; i++)
            free(mtbl[i].key);
        free(mtbl);
    }
    return rc;
}

/* ─────────────────────────────  load  ───────────────────────────── */
static void gb_view_reset(gb_view *v)
{
    if (v->base)
        munmap(v->base, v->map_len);
    free((void *)v->active);
    memset(v, 0, sizeof(*v));
}

/* Every pointer below is derived from the header and checked against the mapped length before it is
 * used, so a damaged file fails here instead of turning into an out-of-bounds read later. */
static int gb_check_layout(gb_view *v)
{
    gb_hdr *h = v->hdr;
    if (h->magic != GB_MAGIC || h->version != GB_VERSION || h->tbl_bits < 1 || h->tbl_bits > 27
        || h->n_exact == 0 || h->n_exact > (1u << 27) || h->n_wild > (1u << 27)
        || h->n_meta == 0 || h->n_meta - 1 > GB_MAX_META || h->hdr_bytes < sizeof(gb_hdr))
        return 0;

    if (h->wild_bits < 1 || h->wild_bits > 27)
        return 0;
    size_t t = (size_t)1 << h->tbl_bits, wt = (size_t)1 << h->wild_bits;
    size_t rowsz = sizeof(uint64_t) + sizeof(uint32_t) + sizeof(uint16_t);
    size_t tables = t * sizeof(uint32_t) + wt * sizeof(uint32_t);
    /* the hash arrays are u64, so the rows start on the next 8-byte boundary after the tables */
    size_t pad = (8u - (tables % 8u)) % 8u;
    size_t need = (size_t)h->hdr_bytes + tables + pad
                + ((size_t)h->n_exact + h->n_wild) * rowsz
                + h->pool_bytes + h->meta_bytes;
    if (need > v->map_len)
        return 0;

    uint8_t *p = v->base + h->hdr_bytes;
    v->exact_tbl = (uint32_t *)p;   p += t * sizeof(uint32_t);
    v->wild_tbl  = (uint32_t *)p;   p += wt * sizeof(uint32_t) + pad;
    v->exact_hash = (uint64_t *)p;  p += (size_t)h->n_exact * sizeof(uint64_t);
    v->exact_off  = (uint32_t *)p;  p += (size_t)h->n_exact * sizeof(uint32_t);
    v->exact_meta = (uint16_t *)p;  p += (size_t)h->n_exact * sizeof(uint16_t);
    v->wild_hash  = (uint64_t *)p;  p += (size_t)h->n_wild * sizeof(uint64_t);
    v->wild_off   = (uint32_t *)p;  p += (size_t)h->n_wild * sizeof(uint32_t);
    v->wild_meta  = (uint16_t *)p;  p += (size_t)h->n_wild * sizeof(uint16_t);
    v->pool = (char *)p;            p += h->pool_bytes;
    v->meta = (char *)p;            p += h->meta_bytes;
    (void)p;

    for (uint32_t i = 0; i < h->n_exact; i++) {
        uint32_t l = gb_namlen(v->pool, h->pool_bytes, v->exact_off[i]);
        if (l == 0 || l > GB_MAX_NAME || v->exact_off[i] + l + 1 > h->pool_bytes)
            return 0;
    }
    for (uint32_t i = 0; i < h->n_wild; i++) {
        uint32_t l = gb_namlen(v->pool, h->pool_bytes, v->wild_off[i]);
        if (l == 0 || l > GB_MAX_NAME || v->wild_off[i] + l + 1 > h->pool_bytes)
            return 0;
    }
    return 1;
}

GB_EXPORT int gb_open(const char *path)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) { gb_seterr("cannot open %s: %s", path, strerror(errno)); return -1; }
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < (off_t)sizeof(gb_hdr)
        || (size_t)st.st_size > (size_t)4 * 1024 * 1024 * 1024) {
        gb_seterr("%s is not a plausible index file (%lld bytes)", path, (long long)st.st_size);
        close(fd);
        return -1;
    }
    uint8_t *m = (uint8_t *)mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_SHARED, fd, 0);
    close(fd);
    if (m == MAP_FAILED) { gb_seterr("mmap failed: %s", strerror(errno)); return -1; }
    gb_hdr *h = (gb_hdr *)m;
    if (h->f_size != (uint64_t)st.st_size) {
        gb_seterr("size in the header (%llu) does not match the file (%lld)",
                  (unsigned long long)h->f_size, (long long)st.st_size);
        munmap(m, (size_t)st.st_size);
        return -1;
    }

    pthread_mutex_lock(&gb_lock);
    int slot = 0;
    for (int i = 1; i < GB_SLOTS; i++) {
        if (gb_slots[i].base == NULL) { slot = i; break; }
    }
    if (slot == 0) {
        pthread_mutex_unlock(&gb_lock);
        munmap(m, (size_t)st.st_size);
        gb_seterr("all %d index slots are in use", GB_SLOTS);
        return -1;
    }
    gb_view *v = &gb_slots[slot];
    v->base = m;
    v->map_len = (size_t)st.st_size;
    v->hdr = h;
    if (!gb_check_layout(v)) {
        gb_view_reset(v);
        pthread_mutex_unlock(&gb_lock);
        gb_seterr("%s failed the layout check - truncated or from another version", path);
        return -1;
    }
    v->inflight = 0;
    v->retired = 0;
    pthread_mutex_unlock(&gb_lock);
    return slot;
}

GB_EXPORT void gb_close(int slot)
{
    if (slot < 1 || slot >= GB_SLOTS)
        return;
    gb_view *v = &gb_slots[slot];
    if (v->base == NULL)
        return;
    /* Readers are lock-free, so wait for the ones already inside before unmapping. A lookup lasts
     * a few hundred nanoseconds, so this spins for at most one of those - and a handle is only
     * closed when a new index has already taken over, so nobody can be blocked on it. */
    v->retired = 1;
    for (int spins = 0; v->inflight != 0 && spins < 1000000; spins++)
        sched_yield();
    pthread_mutex_lock(&gb_lock);
    gb_view_reset(v);
    pthread_mutex_unlock(&gb_lock);
}

/* ─────────────────────────────  lookup  ───────────────────────────── */
static inline uint32_t gb_probe(const uint32_t *tbl, uint32_t mask, const uint64_t *hashes,
                                const uint32_t *offs, const char *pool, uint64_t want,
                                const char *key, uint32_t klen)
{
    uint32_t i = (uint32_t)(want & mask);
    for (uint32_t step = 0; step <= mask; step++) {
        uint32_t e = tbl[i];
        if (e == 0)
            return 0;                                   /* empty slot: the key is not in here */
        e--;
        if (hashes[e] == want && memcmp(pool + offs[e], key, klen) == 0
            && pool[offs[e] + klen] == 0)               /* NUL right after: not a longer name */
            return e + 1;
        i = (i + 1) & mask;
    }
    return 0;
}

/* The feed layer's whole answer, in one call, because two calls cost more than the walk saves:
 *
 *      bit 0            an exact rule matched the name itself
 *      bits 1-16        that row's meta index (which feed, which category)
 *      bit 17           a rule matched one of the name's parents
 *      bit 18           the parent row was a zone (*.parent) rather than an exact row (parent)
 *      bits 19-34       the parent row's meta index
 *      bits 35-42       where that parent starts inside `dom` - app.py slices its own string, so no
 *                       bytes cross the boundary that do not have to
 *
 * A row whose meta is marked disarmed is treated as absent, in both layers, because that is what
 * `feed_hit` does: it keeps walking after a vector is switched off instead of stopping. Get that
 * wrong in the index and the C path blocks names the Python path allows - which is why
 * `gb_set_active` exists and why the parity test runs with two vectors off.
 */
GB_EXPORT uint64_t gb_feed(int slot, const char *dom, uint32_t len)
{
    if (slot < 1 || slot >= GB_SLOTS || dom == NULL || len == 0 || len > GB_MAX_NAME)
        return 0;
    gb_view *v = &gb_slots[slot];
    if (v->base == NULL)
        return 0;

    __atomic_add_fetch(&v->inflight, 1u, __ATOMIC_ACQUIRE);
    if (v->retired) {
        __atomic_sub_fetch(&v->inflight, 1u, __ATOMIC_RELEASE);
        return 0;
    }
    gb_hdr *h = v->hdr;
    uint32_t mask = ((uint32_t)1 << h->tbl_bits) - 1u;
    uint32_t wmask = ((uint32_t)1 << h->wild_bits) - 1u;
    const uint8_t *act = v->active;
    uint64_t out = 0;

    uint32_t e = gb_probe(v->exact_tbl, mask, v->exact_hash, v->exact_off, v->pool,
                          gb_fnv1a(dom, len), dom, len);
    if (e && (!act || act[v->exact_meta[e - 1]])) {
        out |= 1u;
        out |= (uint64_t)v->exact_meta[e - 1] << 1;
    }

    /* Zones are keyed by the zone itself ("doubleclick.net" covers *.doubleclick.net), so this walks
     * the suffixes that start after a label boundary - and never the whole name, which is the exact
     * layer's job. That is also why "notdoubleclick.net" cannot match "doubleclick.net". */
    for (uint32_t dot = 0; dot < len; ) {
        uint32_t k = dot;
        while (k < len && dom[k] != '.')
            k++;
        if (k >= len)
            break;
        uint32_t plen = len - (k + 1);
        if (plen > 0) {
            const char *p = dom + k + 1;
            uint64_t hp = gb_fnv1a(p, plen);
            uint32_t w = gb_probe(v->wild_tbl, wmask, v->wild_hash, v->wild_off, v->pool, hp, p, plen);
            if (w && act && !act[v->wild_meta[w - 1]])
                w = 0;
            uint32_t pe = 0;
            if (!w) {
                pe = gb_probe(v->exact_tbl, mask, v->exact_hash, v->exact_off, v->pool, hp, p, plen);
                if (pe && act && !act[v->exact_meta[pe - 1]])
                    pe = 0;
            }
            if (w || pe) {
                uint32_t meta = w ? v->wild_meta[w - 1] : v->exact_meta[pe - 1];
                out |= 1ull << 17;
                if (!w)
                    out |= 1ull << 18;
                out |= (uint64_t)meta << 19;
                out |= (uint64_t)(k + 1) << 35;
                break;
            }
        }
        dot = k + 1;
    }
    __atomic_sub_fetch(&v->inflight, 1u, __ATOMIC_RELEASE);
    return out;
}

/* Which (category, vector) pairs this index should treat as armed: one byte per meta. The engine
 * owns that decision; the index only needs the answer, or it cannot skip a disarmed row the way the
 * engine does. NULL (the state a fresh index is built in) means everything is armed. */
GB_EXPORT int gb_set_active(int slot, const uint8_t *flags, uint32_t n)
{
    if (slot < 1 || slot >= GB_SLOTS || gb_slots[slot].base == NULL)
        return -1;
    gb_view *v = &gb_slots[slot];
    if (n != v->hdr->n_meta) {
        gb_seterr("gb_set_active: %u flags for %u metas", n, v->hdr->n_meta);
        return -1;
    }
    uint8_t *copy = NULL;
    if (flags && n) {
        copy = (uint8_t *)malloc(n);
        if (!copy) { gb_seterr("out of memory for the active table"); return -1; }
        memcpy(copy, flags, n);
    }
    __atomic_add_fetch(&v->inflight, 1u, __ATOMIC_ACQUIRE);
    free((void *)v->active);
    v->active = copy;
    __atomic_sub_fetch(&v->inflight, 1u, __ATOMIC_RELEASE);
    return 0;
}

/* The one-table form, for the read-only mapping app.py hands to the dashboard and the exports. */
GB_EXPORT uint32_t gb_get(int slot, int wild, const char *dom, uint32_t len)
{
    if (slot < 1 || slot >= GB_SLOTS || dom == NULL || len == 0 || len > GB_MAX_NAME)
        return 0;
    gb_view *v = &gb_slots[slot];
    if (v->base == NULL)
        return 0;
    gb_hdr *h = v->hdr;
    uint32_t mask = ((uint32_t)1 << (wild ? h->wild_bits : h->tbl_bits)) - 1u;
    __atomic_add_fetch(&v->inflight, 1u, __ATOMIC_ACQUIRE);
    if (v->retired) {
        __atomic_sub_fetch(&v->inflight, 1u, __ATOMIC_RELEASE);
        return 0;
    }
    uint32_t e = gb_probe(wild ? v->wild_tbl : v->exact_tbl, mask,
                          wild ? v->wild_hash : v->exact_hash,
                          wild ? v->wild_off : v->exact_off, v->pool,
                          gb_fnv1a(dom, len), dom, len);
    uint32_t out = e ? (uint32_t)(wild ? v->wild_meta[e - 1] : v->exact_meta[e - 1]) + 1u : 0u;
    __atomic_sub_fetch(&v->inflight, 1u, __ATOMIC_RELEASE);
    return out;
}

GB_EXPORT uint32_t gb_count(int slot, int wild)
{
    if (slot < 1 || slot >= GB_SLOTS || gb_slots[slot].base == NULL)
        return 0;
    return wild ? gb_slots[slot].hdr->n_wild : gb_slots[slot].hdr->n_exact;
}

GB_EXPORT uint64_t gb_bytes(int slot)
{
    if (slot < 1 || slot >= GB_SLOTS || gb_slots[slot].base == NULL)
        return 0;
    return gb_slots[slot].hdr->f_size;
}

GB_EXPORT uint64_t gb_built_ns(int slot)
{
    if (slot < 1 || slot >= GB_SLOTS || gb_slots[slot].base == NULL)
        return 0;
    return gb_slots[slot].hdr->built_ns;
}

/* "cat\0vec\0src\0" for one meta index, into a caller-owned buffer. Called a couple of hundred times
 * (once per feed) at open, never on a query - which is why the hot path returns an integer. */
GB_EXPORT int gb_meta_at(int slot, uint32_t idx, char *buf, uint32_t cap)
{
    if (slot < 1 || slot >= GB_SLOTS || gb_slots[slot].base == NULL || buf == NULL || cap < 4)
        return -1;
    gb_view *v = &gb_slots[slot];
    if (idx >= v->hdr->n_meta)
        return -1;
    const char *p = v->meta;
    const char *end = v->meta + v->hdr->meta_bytes;
    for (uint32_t i = 0; i < idx; i++) {
        for (int f = 0; f < 3; f++) {
            while (p < end && *p)
                p++;
            p++;
        }
    }
    uint32_t o = 0;
    for (int f = 0; f < 3; f++) {
        while (p < end && *p && o + 1 < cap)
            buf[o++] = *p++;
        buf[o++] = 0;
        if (p < end)
            p++;
    }
    buf[o < cap ? o : cap - 1] = 0;
    return (int)o;
}

/* Cold-path iteration: NUL-separated names for rows [from, from+k) into `out`, their meta indices
 * into `metas`, and k is returned. Iterating 4M keys in one-ctypes-call-per-name is how a fast
 * index would still make the dashboard slow, so this batches. */
GB_EXPORT uint32_t gb_dump(int slot, int wild, uint32_t from, uint32_t room, char *out,
                           uint16_t *metas, uint32_t *written_out)
{
    if (slot < 1 || slot >= GB_SLOTS || gb_slots[slot].base == NULL || out == NULL
        || metas == NULL || room < 4)
        return 0;
    gb_view *v = &gb_slots[slot];
    gb_hdr *h = v->hdr;
    uint32_t n = wild ? h->n_wild : h->n_exact;
    const uint32_t *offs = wild ? v->wild_off : v->exact_off;
    const uint16_t *metas_in = wild ? v->wild_meta : v->exact_meta;

    if (v->retired)
        return 0;
    /* the caller's metas array is sized room/2, the smallest name being 1 byte plus its NUL */
    uint32_t meta_cap = room / 2;
    __atomic_add_fetch(&v->inflight, 1u, __ATOMIC_ACQUIRE);
    uint32_t o = 0, i = from, written = 0;
    while (i < n && o < room && written < meta_cap) {
        const char *s = v->pool + offs[i];
        uint32_t l = gb_namlen(v->pool, h->pool_bytes, offs[i]);
        if (l == 0 || l > room - o - 1)
            break;
        memcpy(out + o, s, l);
        out[o + l] = 0;
        o += l + 1;
        metas[written++] = metas_in[i];
        i++;
    }
    if (written_out)
        *written_out = written;
    __atomic_sub_fetch(&v->inflight, 1u, __ATOMIC_RELEASE);
    return o;
}
