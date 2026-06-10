/*
 *  Copyright (C) 2026 Radpoint and/or its affiliates. All rights reserved.
 *
 *  DICOM medical-imaging container handler.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA 02110-1301, USA.
 */

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include <string.h>

#include <zlib.h>

#include "clamav.h"
#include "others.h"
#include "scanners.h"
#include "fmap.h"
#include "dicom.h"

#ifndef MIN
#define MIN(x, y) ((x) < (y) ? (x) : (y))
#endif

/* File layout: [0..128) preamble, [128..132) "DICM", [132..) File Meta group
 * (group 0002, always Explicit VR Little Endian), then the dataset in the
 * transfer syntax negotiated by (0002,0010). */
#define DICOM_DATASET_DEFAULT_OFFSET 132

#define DICOM_TAG(g, e) (((uint32_t)(g) << 16) | (e))
#define TAG_TRANSFER_SYNTAX_UID DICOM_TAG(0x0002, 0x0010)
#define TAG_ENCAPSULATED_DOC DICOM_TAG(0x0042, 0x0011)
#define TAG_PIXEL_DATA DICOM_TAG(0x7FE0, 0x0010)
#define TAG_ITEM DICOM_TAG(0xFFFE, 0xE000)
#define TAG_ITEM_DELIM DICOM_TAG(0xFFFE, 0xE00D)
#define TAG_SEQ_DELIM DICOM_TAG(0xFFFE, 0xE0DD)

#define DICOM_UNDEFINED_LENGTH 0xFFFFFFFFu
#define DICOM_MAX_SQ_DEPTH 16

/* Transfer syntax UIDs that change how the dataset must be read */
#define TS_IMPLICIT_VR_LE "1.2.840.10008.1.2"
#define TS_EXPLICIT_VR_LE "1.2.840.10008.1.2.1"
#define TS_DEFLATED_VR_LE "1.2.840.10008.1.2.1.99"
#define TS_EXPLICIT_VR_BE "1.2.840.10008.1.2.2"
#define TS_ENCAP_PREFIX "1.2.840.10008.1.2.4." /* JPEG/JPEG-LS/J2K family */
#define TS_RLE "1.2.840.10008.1.2.5"

typedef struct dicom_metadata {
    size_t dataset_offset; /* first byte after the File Meta group */
    char ts_uid[64];       /* TransferSyntaxUID, NUL-terminated, may be "" */
    bool explicit_vr;
    bool big_endian;   /* retired Explicit VR Big Endian */
    bool deflated;     /* dataset is a raw DEFLATE stream */
    bool encapsulated; /* pixel data arrives as compressed fragments */
} dicom_metadata;

/* VRs whose explicit form carries a 2-byte reserved field + 32-bit length */
static bool vr_has_long_length(const uint8_t vr[2])
{
    static const char *long_vrs[] = {"OB", "OD", "OF", "OL", "OV", "OW",
                                     "SQ", "SV", "UC", "UN", "UR", "UT", NULL};
    size_t i;

    for (i = 0; NULL != long_vrs[i]; i++) {
        if (vr[0] == (uint8_t)long_vrs[i][0] && vr[1] == (uint8_t)long_vrs[i][1]) {
            return true;
        }
    }
    return false;
}

static bool vr_is_valid(const uint8_t vr[2])
{
    /* Every standard VR is two uppercase ASCII letters */
    return (vr[0] >= 'A' && vr[0] <= 'Z' && vr[1] >= 'A' && vr[1] <= 'Z');
}

static void dicom_apply_transfer_syntax(dicom_metadata *meta)
{
    if (0 == strcmp(meta->ts_uid, TS_IMPLICIT_VR_LE)) {
        meta->explicit_vr = false;
    } else if (0 == strcmp(meta->ts_uid, TS_EXPLICIT_VR_LE)) {
        /* defaults */
    } else if (0 == strcmp(meta->ts_uid, TS_DEFLATED_VR_LE)) {
        meta->deflated = true;
    } else if (0 == strcmp(meta->ts_uid, TS_EXPLICIT_VR_BE)) {
        meta->big_endian = true;
    } else if (0 == strncmp(meta->ts_uid, TS_ENCAP_PREFIX, strlen(TS_ENCAP_PREFIX)) ||
               0 == strcmp(meta->ts_uid, TS_RLE)) {
        meta->encapsulated = true;
    } else if ('\0' != meta->ts_uid[0]) {
        /* Unknown/private transfer syntax: keep Explicit VR LE defaults and
         * treat pixel data as potentially encapsulated so undefined-length
         * (7FE0,0010) still gets fragment-walked. */
        cli_dbgmsg("dicom: unknown transfer syntax UID '%s'\n", meta->ts_uid);
        meta->encapsulated = true;
    }
}

/*
 * Parse the File Meta Information group (0002,xxxx), which is always encoded
 * Explicit VR Little Endian regardless of the dataset transfer syntax.
 *
 * Fills `meta`. Never trusts (0002,0000) FileMetaInformationGroupLength;
 * instead walks elements until the group changes. On a malformed meta group,
 * logs and leaves the Explicit-VR-LE defaults with dataset_offset at the
 * point parsing stopped — the caller's walk is best-effort and the engine's
 * raw scan covers the bytes regardless.
 */
static void dicom_parse_file_meta(cli_ctx *ctx, dicom_metadata *meta)
{
    fmap_t *map  = ctx->fmap;
    size_t off   = DICOM_DATASET_DEFAULT_OFFSET;
    bool got_any = false;

    memset(meta, 0, sizeof(*meta));
    meta->explicit_vr    = true;
    meta->dataset_offset = DICOM_DATASET_DEFAULT_OFFSET;

    while (off + 8 <= map->len) {
        const uint8_t *p = fmap_need_off_once(map, off, 8);
        uint16_t group, element;
        uint8_t vr[2];
        uint32_t length;
        size_t header_len;

        if (NULL == p) {
            break;
        }

        group   = (uint16_t)cli_readint16(p);
        element = (uint16_t)cli_readint16(p + 2);

        if (0x0002 != group) {
            /* end of File Meta group: dataset starts here */
            break;
        }

        vr[0] = p[4];
        vr[1] = p[5];
        if (!vr_is_valid(vr)) {
            cli_dbgmsg("dicom: invalid VR %02x%02x in file meta at %zu\n",
                       vr[0], vr[1], off);
            break;
        }

        if (vr_has_long_length(vr)) {
            const uint8_t *q = fmap_need_off_once(map, off + 8, 4);
            if (NULL == q) {
                break;
            }
            length     = (uint32_t)cli_readint32(q);
            header_len = 12;
        } else {
            length     = (uint16_t)cli_readint16(p + 6);
            header_len = 8;
        }

        if (length > map->len || off + header_len + length > map->len) {
            cli_dbgmsg("dicom: file meta element (%04x,%04x) length %u exceeds file size\n",
                       group, element, length);
            break;
        }

        if (TAG_TRANSFER_SYNTAX_UID == DICOM_TAG(group, element) && length > 0) {
            size_t copy_len      = MIN(length, sizeof(meta->ts_uid) - 1);
            const uint8_t *value = fmap_need_off_once(map, off + header_len, copy_len);
            if (NULL != value) {
                memcpy(meta->ts_uid, value, copy_len);
                meta->ts_uid[copy_len] = '\0';
                /* UI values are NUL-padded to even length; some writers pad
                 * with spaces. Trim. */
                while (copy_len > 0 && ('\0' == meta->ts_uid[copy_len - 1] ||
                                        ' ' == meta->ts_uid[copy_len - 1])) {
                    meta->ts_uid[--copy_len] = '\0';
                }
            }
        }

        got_any = true;
        off += header_len + length;
        meta->dataset_offset = off;
    }

    if (!got_any) {
        cli_dbgmsg("dicom: no file meta group found; assuming Explicit VR LE dataset at %u\n",
                   DICOM_DATASET_DEFAULT_OFFSET);
    }

    dicom_apply_transfer_syntax(meta);
}

/*
 * Re-inject one extracted region into the engine. The engine re-detects the
 * child's type and recurses (ZIP/PNG/PE/PDF inside a fragment all get their
 * native parsers) under MaxRecursion/MaxFiles/MaxScanSize.
 *
 * Children over the limits are skipped, not fatal. Child parse errors do not
 * fail the DICOM scan (the raw scan of the whole file still happens at this
 * type's layer). Only CL_VIRUS and hard engine errors propagate.
 */
static cl_error_t dicom_scan_child(cli_ctx *ctx, size_t off, size_t len,
                                   const char *name, bool *found)
{
    cl_error_t ret;

    if (0 == len) {
        return CL_SUCCESS;
    }

    ret = cli_checklimits("dicom", ctx, (uint64_t)len, 0, 0);
    if (CL_SUCCESS != ret) {
        cli_dbgmsg("dicom: skipping %s (%zu bytes) due to limits\n", name, len);
        return CL_SUCCESS;
    }

    ret = cli_magic_scan_nested_fmap_type(ctx->fmap, off, len, ctx,
                                          CL_TYPE_ANY, name, LAYER_ATTRIBUTES_NONE);
    if (CL_VIRUS == ret) {
        *found = true;
        if (SCAN_ALLMATCHES) {
            return CL_SUCCESS;
        }
        return CL_VIRUS;
    }
    if (CL_ETIMEOUT == ret || CL_EMEM == ret) {
        return ret;
    }
    if (CL_SUCCESS != ret) {
        cli_dbgmsg("dicom: child %s scan returned %d, continuing\n", name, ret);
    }
    return CL_SUCCESS;
}

/*
 * Walk the item sequence of encapsulated pixel data: (FFFE,E000) items up to
 * the (FFFE,E0DD) sequence delimiter. Item 0 is normally the Basic Offset
 * Table, but malformed writers omit it — scan every non-empty item rather
 * than risk skipping a frame. Each item payload is a compressed frame
 * (JPEG/J2K/RLE), which is exactly the content the raw signature scan cannot
 * see through.
 *
 * *endpos is set to the first byte after the sequence delimiter (or where
 * parsing stopped).
 */
static cl_error_t dicom_scan_encap_pixeldata(cli_ctx *ctx, size_t off, size_t end,
                                             unsigned *n_extracted, bool *found,
                                             size_t *endpos)
{
    fmap_t *map    = ctx->fmap;
    cl_error_t ret = CL_SUCCESS;
    unsigned frag  = 0;

    while (off + 8 <= end) {
        const uint8_t *p = fmap_need_off_once(map, off, 8);
        uint16_t group, element;
        uint32_t length;

        if (NULL == p) {
            ret = CL_EPARSE;
            break;
        }
        group   = (uint16_t)cli_readint16(p);
        element = (uint16_t)cli_readint16(p + 2);
        length  = (uint32_t)cli_readint32(p + 4);
        off += 8;

        if (TAG_SEQ_DELIM == DICOM_TAG(group, element)) {
            break;
        }
        if (TAG_ITEM != DICOM_TAG(group, element) ||
            DICOM_UNDEFINED_LENGTH == length || off + length > end) {
            cli_dbgmsg("dicom: malformed pixel-data fragment at %zu (tag %04x,%04x len %u)\n",
                       off - 8, group, element, length);
            ret = CL_EPARSE;
            break;
        }

        if (length > 0) {
            char name[48];
            snprintf(name, sizeof(name), "dicom_pixel_fragment_%u", frag);
            ret = dicom_scan_child(ctx, off, length, name, found);
            if (CL_SUCCESS != ret) {
                break;
            }
            (*n_extracted)++;
        }
        frag++;
        off += length;

        if (CL_SUCCESS != cli_checktimelimit(ctx)) {
            ret = CL_ETIMEOUT;
            break;
        }
    }

    *endpos = off;
    return ret;
}

/*
 * Inflate a Deflated-transfer-syntax dataset (raw DEFLATE, RFC 1951, no zlib
 * header) and re-inject the inflated dataset into the engine. Output is
 * capped at the engine's maxscansize (this is the zip-bomb guard); inflation
 * stops at the cap and scans what was produced. The inflated bytes are a DICOM
 * dataset without the preamble/"DICM" lead, so the engine raw-scans them — for
 * the standard deflated transfer syntax pixel data is native (uncompressed),
 * so signatures in the data are visible after this single inflate.
 */
static cl_error_t dicom_scan_deflated(cli_ctx *ctx, size_t off, bool *found)
{
    fmap_t *map      = ctx->fmap;
    cl_error_t ret   = CL_SUCCESS;
    z_stream strm    = {0};
    uint8_t *out     = NULL;
    size_t out_cap   = 0;
    size_t out_len   = 0;
    uint64_t max_out = ctx->engine ? ctx->engine->maxscansize : 0;
    const uint8_t *in;
    size_t in_len;
    uint8_t chunk[BUFSIZ];

    if (off >= map->len) {
        return CL_SUCCESS;
    }
    in_len = map->len - off;
    in     = fmap_need_off_once(map, off, in_len);
    if (NULL == in) {
        return CL_SUCCESS;
    }

    if (0 == max_out || max_out > CLI_MAX_ALLOCATION) {
        max_out = CLI_MAX_ALLOCATION;
    }

    if (Z_OK != inflateInit2(&strm, -MAX_WBITS)) {
        cli_dbgmsg("dicom: inflateInit2 failed for deflated dataset\n");
        return CL_SUCCESS;
    }
    strm.next_in  = (Bytef *)in;
    strm.avail_in = (uInt)MIN(in_len, (size_t)UINT_MAX);

    do {
        int zret;

        strm.next_out  = chunk;
        strm.avail_out = sizeof(chunk);
        zret           = inflate(&strm, Z_NO_FLUSH);

        if (Z_OK != zret && Z_STREAM_END != zret && Z_BUF_ERROR != zret) {
            cli_dbgmsg("dicom: inflate error %d on deflated dataset\n", zret);
            break;
        }

        size_t produced = sizeof(chunk) - strm.avail_out;
        if (produced > 0) {
            if (out_len + produced > max_out) {
                cli_dbgmsg("dicom: deflated dataset exceeds maxscansize, truncating\n");
                produced = (size_t)(max_out - out_len);
                zret     = Z_STREAM_END;
            }
            if (out_len + produced > out_cap) {
                size_t new_cap = out_cap ? out_cap * 2 : (size_t)(64 * 1024);
                uint8_t *tmp;
                while (new_cap < out_len + produced) {
                    new_cap *= 2;
                }
                tmp = cli_max_realloc(out, new_cap);
                if (NULL == tmp) {
                    ret = CL_EMEM;
                    break;
                }
                out     = tmp;
                out_cap = new_cap;
            }
            memcpy(out + out_len, chunk, produced);
            out_len += produced;
        }

        if (Z_STREAM_END == zret || (0 == strm.avail_in && 0 == produced)) {
            break;
        }
        if (CL_SUCCESS != cli_checktimelimit(ctx)) {
            ret = CL_ETIMEOUT;
            break;
        }
    } while (1);

    inflateEnd(&strm);

    if (CL_SUCCESS == ret && out_len > 0) {
        cli_dbgmsg("dicom: inflated deflated dataset to %zu bytes\n", out_len);
        ret = cli_magic_scan_buff(out, out_len, ctx, "dicom_deflated_dataset",
                                  LAYER_ATTRIBUTES_NONE);
        if (CL_VIRUS == ret) {
            *found = true;
            ret    = SCAN_ALLMATCHES ? CL_SUCCESS : CL_VIRUS;
        }
    }

    if (NULL != out) {
        free(out);
    }
    return ret;
}

static cl_error_t dicom_walk_elements(cli_ctx *ctx, const dicom_metadata *meta,
                                      size_t off, size_t end, unsigned depth,
                                      unsigned *n_extracted, bool *found,
                                      size_t *endpos);

/*
 * Walk the (FFFE,E000) items of a sequence (SQ). `lim` bounds the sequence:
 * for a defined-length SQ it is the end of the value; for undefined length it
 * is the enclosing boundary, and the (FFFE,E0DD) delimiter terminates the
 * loop. Each item body is a nested dataset and is walked recursively.
 */
static cl_error_t dicom_walk_sq_items(cli_ctx *ctx, const dicom_metadata *meta,
                                      size_t off, size_t lim, unsigned depth,
                                      unsigned *n_extracted, bool *found,
                                      size_t *endpos)
{
    fmap_t *map    = ctx->fmap;
    cl_error_t ret = CL_SUCCESS;

    while (off + 8 <= lim) {
        const uint8_t *p = fmap_need_off_once(map, off, 8);
        uint16_t group, element;
        uint32_t length;
        size_t stop = 0;

        if (NULL == p) {
            ret = CL_EPARSE;
            break;
        }
        group   = (uint16_t)cli_readint16(p);
        element = (uint16_t)cli_readint16(p + 2);
        length  = (uint32_t)cli_readint32(p + 4);
        off += 8;

        if (TAG_SEQ_DELIM == DICOM_TAG(group, element)) {
            break;
        }
        if (TAG_ITEM != DICOM_TAG(group, element)) {
            cli_dbgmsg("dicom: expected SQ item at %zu, got (%04x,%04x)\n",
                       off - 8, group, element);
            ret = CL_EPARSE;
            break;
        }

        if (DICOM_UNDEFINED_LENGTH == length) {
            /* item body runs to its (FFFE,E00D) delimiter */
            ret = dicom_walk_elements(ctx, meta, off, lim, depth + 1,
                                      n_extracted, found, &stop);
            off = stop;
        } else {
            if (off + length > lim) {
                cli_dbgmsg("dicom: SQ item length %u exceeds sequence bounds at %zu\n",
                           length, off - 8);
                ret = CL_EPARSE;
                break;
            }
            ret = dicom_walk_elements(ctx, meta, off, off + length, depth + 1,
                                      n_extracted, found, &stop);
            off += length;
        }
        if (CL_SUCCESS != ret) {
            break;
        }
    }

    *endpos = off;
    return ret;
}

/*
 * Walk data elements in [off, end). At depth > 0 (inside an undefined-length
 * SQ item) an (FFFE,E00D) item delimiter terminates the walk; *endpos is set
 * past it.
 *
 * Extraction targets:
 *   - (7FE0,0010) PixelData, undefined length -> encapsulated fragment walk
 *   - (7FE0,0010) PixelData, defined length   -> re-inject (polyglot guard)
 *   - (0042,0011) EncapsulatedDocument        -> re-inject (PDF/CDA get their
 *                                                native parser, which the raw
 *                                                scan at this layer won't run)
 *   - SQ / undefined-length elements          -> recurse into items
 *
 * Implicit-VR limitation (documented): without a tag dictionary a
 * defined-length SQ is indistinguishable from a binary blob, so it is
 * skipped opaquely; undefined-length elements are still recursed.
 */
static cl_error_t dicom_walk_elements(cli_ctx *ctx, const dicom_metadata *meta,
                                      size_t off, size_t end, unsigned depth,
                                      unsigned *n_extracted, bool *found,
                                      size_t *endpos)
{
    fmap_t *map    = ctx->fmap;
    cl_error_t ret = CL_SUCCESS;

    if (depth > DICOM_MAX_SQ_DEPTH) {
        cli_dbgmsg("dicom: SQ nesting deeper than %u, stopping descent\n",
                   DICOM_MAX_SQ_DEPTH);
        *endpos = end;
        return CL_SUCCESS;
    }

    while (off + 8 <= end) {
        const uint8_t *p = fmap_need_off_once(map, off, 8);
        uint16_t group, element;
        uint32_t tag;
        uint8_t vr[2] = {0, 0};
        uint32_t length;
        size_t header_len;
        bool is_sq = false;

        if (NULL == p) {
            ret = CL_EPARSE;
            break;
        }
        group   = (uint16_t)cli_readint16(p);
        element = (uint16_t)cli_readint16(p + 2);
        tag     = DICOM_TAG(group, element);

        if (TAG_ITEM_DELIM == tag || TAG_SEQ_DELIM == tag) {
            off += 8;
            if (depth > 0) {
                break; /* end of this item */
            }
            cli_dbgmsg("dicom: stray delimiter (%04x,%04x) at top level\n",
                       group, element);
            continue;
        }

        if (meta->explicit_vr && TAG_ITEM != tag) {
            vr[0] = p[4];
            vr[1] = p[5];
            if (!vr_is_valid(vr)) {
                cli_dbgmsg("dicom: invalid VR %02x%02x at %zu\n", vr[0], vr[1], off);
                ret = CL_EPARSE;
                break;
            }
            if (vr_has_long_length(vr)) {
                const uint8_t *q = fmap_need_off_once(map, off + 8, 4);
                if (NULL == q) {
                    ret = CL_EPARSE;
                    break;
                }
                length     = (uint32_t)cli_readint32(q);
                header_len = 12;
            } else {
                length     = (uint16_t)cli_readint16(p + 6);
                header_len = 8;
            }
            is_sq = ('S' == vr[0] && 'Q' == vr[1]);
        } else {
            /* implicit VR (or item tag): 32-bit length, no VR field */
            length     = (uint32_t)cli_readint32(p + 4);
            header_len = 8;
        }

        if (DICOM_UNDEFINED_LENGTH == length) {
            size_t stop = 0;

            if (TAG_PIXEL_DATA == tag) {
                ret = dicom_scan_encap_pixeldata(ctx, off + header_len, end,
                                                 n_extracted, found, &stop);
            } else {
                /* SQ, or UN/implicit element parsed as a sequence */
                ret = dicom_walk_sq_items(ctx, meta, off + header_len, end,
                                          depth, n_extracted, found, &stop);
            }
            if (CL_SUCCESS != ret) {
                break;
            }
            off = stop;
            continue;
        }

        if (length > map->len || off + header_len + length > end) {
            cli_dbgmsg("dicom: element (%04x,%04x) length %u exceeds bounds at %zu\n",
                       group, element, length, off);
            ret = CL_EPARSE;
            break;
        }

        if (is_sq) {
            size_t stop = 0;
            ret = dicom_walk_sq_items(ctx, meta, off + header_len,
                                      off + header_len + length, depth,
                                      n_extracted, found, &stop);
            if (CL_SUCCESS != ret) {
                break;
            }
        } else if (TAG_PIXEL_DATA == tag) {
            ret = dicom_scan_child(ctx, off + header_len, length,
                                   "dicom_pixel_data", found);
            if (CL_SUCCESS != ret) {
                break;
            }
            (*n_extracted)++;
        } else if (TAG_ENCAPSULATED_DOC == tag) {
            ret = dicom_scan_child(ctx, off + header_len, length,
                                   "dicom_encapsulated_document", found);
            if (CL_SUCCESS != ret) {
                break;
            }
            (*n_extracted)++;
        }

        off += header_len + length;

        if (CL_SUCCESS != cli_checktimelimit(ctx)) {
            ret = CL_ETIMEOUT;
            break;
        }
    }

    *endpos = off;
    return ret;
}

cl_error_t cli_scandicom(cli_ctx *ctx)
{
    dicom_metadata meta;
    cl_error_t ret;
    unsigned n_extracted = 0;
    bool found           = false;
    size_t endpos        = 0;

    if (NULL == ctx || NULL == ctx->fmap) {
        return CL_ENULLARG;
    }

    cli_dbgmsg("in cli_scandicom (%zu bytes)\n", (size_t)ctx->fmap->len);

    dicom_parse_file_meta(ctx, &meta);

    cli_dbgmsg("dicom: transfer syntax '%s' -> %s VR, %s endian%s%s; dataset at %zu\n",
               meta.ts_uid[0] ? meta.ts_uid : "(none)",
               meta.explicit_vr ? "explicit" : "implicit",
               meta.big_endian ? "big" : "little",
               meta.deflated ? ", deflated" : "",
               meta.encapsulated ? ", encapsulated pixel data" : "",
               meta.dataset_offset);

    if (meta.big_endian) {
        /* retired Explicit VR Big Endian: rare; raw scan only for now */
        cli_dbgmsg("dicom: big-endian transfer syntax not walked\n");
        return CL_SUCCESS;
    }
    if (meta.deflated) {
        ret = dicom_scan_deflated(ctx, meta.dataset_offset, &found);
        if (found) {
            return CL_VIRUS;
        }
        return (CL_EPARSE == ret) ? CL_SUCCESS : ret;
    }

    ret = dicom_walk_elements(ctx, &meta, meta.dataset_offset, ctx->fmap->len,
                              0, &n_extracted, &found, &endpos);

    cli_dbgmsg("dicom: walk ended at %zu/%zu, %u object(s) extracted, ret %d\n",
               endpos, (size_t)ctx->fmap->len, n_extracted, ret);

    if (found) {
        return CL_VIRUS;
    }
    if (CL_EPARSE == ret) {
        /* malformed element stream: not an error verdict — the engine's raw
         * scan of this layer covers the bytes the walk could not interpret */
        cli_dbgmsg("dicom: malformed element stream, walk stopped early\n");
        return CL_SUCCESS;
    }
    return ret;
}
