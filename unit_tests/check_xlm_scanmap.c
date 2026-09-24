/*
 * Copyright (C) 2026 Cisco Systems, Inc. and/or its affiliates. All rights reserved.
 *
 * Exercise the public scan-map API with XLM regression inputs.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "clamav.h"

static cl_error_t scan_file_as_map(const char *path, const struct cl_engine *engine)
{
    cl_error_t status   = CL_EOPEN;
    cl_fmap_t *map      = NULL;
    FILE *file          = NULL;
    unsigned char *data = NULL;
    long file_size;
    const char *virus_name = NULL;
    unsigned long scanned  = 0;
    struct cl_scan_options options;

    file = fopen(path, "rb");
    if (NULL == file || 0 != fseek(file, 0, SEEK_END) || 0 > (file_size = ftell(file)) ||
        0 != fseek(file, 0, SEEK_SET)) {
        goto done;
    }

    data = malloc((size_t)file_size);
    if (NULL == data) {
        status = CL_EMEM;
        goto done;
    }
    if ((size_t)file_size != fread(data, 1, (size_t)file_size, file)) {
        status = CL_EREAD;
        goto done;
    }

    map = cl_fmap_open_memory(data, (size_t)file_size);
    if (NULL == map) {
        status = CL_EMEM;
        goto done;
    }

    memset(&options, 0, sizeof(options));
    options.parse = CL_SCAN_PARSE_OLE2;
    status        = cl_scanmap_callback(map, path, &virus_name, &scanned, engine, &options, NULL);

done:
    if (NULL != map) {
        cl_fmap_close(map);
    }
    free(data);
    if (NULL != file) {
        fclose(file);
    }
    return status;
}

int main(int argc, char **argv)
{
    cl_error_t status;
    struct cl_engine *engine     = NULL;
    unsigned int signature_count = 0;
    cl_error_t expected_status;
    int i;

    if (argc < 4 || (0 != strcmp(argv[2], "clean") && 0 != strcmp(argv[2], "virus"))) {
        fprintf(stderr, "Usage: %s DATABASE {clean|virus} FILE...\n", argv[0]);
        return 2;
    }
    expected_status = 0 == strcmp(argv[2], "virus") ? CL_VIRUS : CL_SUCCESS;

    status = cl_init(CL_INIT_DEFAULT);
    if (CL_SUCCESS != status || NULL == (engine = cl_engine_new())) {
        fprintf(stderr, "Failed to initialize ClamAV: %s\n", cl_strerror(status));
        return 2;
    }
    status = cl_load(argv[1], engine, &signature_count, CL_DB_STDOPT);
    if (CL_SUCCESS != status) {
        fprintf(stderr, "Failed to load signature database %s: %s\n", argv[1], cl_strerror(status));
        cl_engine_free(engine);
        return 2;
    }
    status = cl_engine_compile(engine);
    if (CL_SUCCESS != status) {
        fprintf(stderr, "Failed to compile ClamAV engine: %s\n", cl_strerror(status));
        cl_engine_free(engine);
        return 2;
    }

    for (i = 3; i < argc; i++) {
        status = scan_file_as_map(argv[i], engine);
        if (expected_status != status) {
            fprintf(stderr, "Scan-map returned %s for %s; expected %s\n",
                    cl_strerror(status), argv[i], cl_strerror(expected_status));
            cl_engine_free(engine);
            return 1;
        }
    }

    cl_engine_free(engine);
    return 0;
}
