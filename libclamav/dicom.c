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

#include "clamav.h"
#include "others.h"
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

cl_error_t cli_scandicom(cli_ctx *ctx)
{
    dicom_metadata meta;

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

    /* TODO (next commits):
     *   - deflated: inflate the dataset (raw DEFLATE) into a buffer under
     *     cli_checklimits, then cli_magic_scan_buff() it.
     *   - element walk of the dataset: extract encapsulated pixel-data
     *     fragments (7FE0,0010 undefined length), embedded documents
     *     (0042,0011) and native OB/OW blobs, re-injecting each via
     *     cli_magic_scan_nested_fmap_type().
     */

    return CL_SUCCESS;
}
