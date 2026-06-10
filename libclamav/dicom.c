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

#include "clamav.h"
#include "others.h"
#include "fmap.h"
#include "dicom.h"

cl_error_t cli_scandicom(cli_ctx *ctx)
{
    if (NULL == ctx || NULL == ctx->fmap) {
        return CL_ENULLARG;
    }

    /* Stub: file-type detection + dispatch are wired; structural parsing lands next.
     *
     * TODO (in order):
     *   1. Parse File Meta group (0002,*) -> TransferSyntaxUID; set VR mode,
     *      detect deflated / encapsulated encodings.
     *   2. Port the venkman element walk (tagInfo[] / vrInfo[]) onto fmap reads.
     *   3. Extract & re-inject via cli_magic_scan_nested_fmap_type() /
     *      cli_magic_scan_buff():
     *        - encapsulated pixel-data fragments (7FE0,0010 undefined length),
     *        - deflated datasets (1.2.840.10008.1.2.1.99),
     *        - embedded documents (0042,0011),
     *        - native OB/OW blobs.
     *   4. cli_checklimits() before every child; bounds-check every read via
     *      fmap_need_off_once().
     */
    cli_dbgmsg("in cli_scandicom: detected DICOM (%zu bytes); stub, no parsing yet\n",
               (size_t)ctx->fmap->len);

    return CL_SUCCESS;
}
