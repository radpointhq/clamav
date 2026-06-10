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

#ifndef __DICOM_H
#define __DICOM_H

#if HAVE_CONFIG_H
#include "clamav-config.h"
#endif

#include "others.h"

/*
 * Scan a DICOM file. Walks the data-element stream and re-injects embedded
 * objects (encapsulated/compressed pixel data, deflated datasets, embedded
 * documents) into the engine so that nested content is scanned recursively
 * under the usual MaxRecursion / MaxFiles / MaxScanSize limits.
 *
 * Returns CL_VIRUS on detection, CL_SUCCESS otherwise (including on a
 * malformed element stream, which is logged but not treated as a scan error).
 */
cl_error_t cli_scandicom(cli_ctx *ctx);

#endif /* __DICOM_H */
