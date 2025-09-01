/**
 * Copyright (C) 2014, 2015, 2017, 2018, 2020, 2021, 2025 Genome Research
 * Ltd. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * @file read.c
 * @author Keith James <kdj@sanger.ac.uk>
 */

#include <assert.h>

#include "config.h"
#include "compat_checksum.h"
#include "json.h"
#include "read.h"
#include "utilities.h"

static char *do_slurp(baton_session_t *session, rodsPath_t *rods_path,
                      const size_t buffer_size, baton_error_t *error) {
    data_obj_file_t *obj_file = NULL;
    const int           flags = 0;

    if (buffer_size == 0) {
        set_baton_error(error, -1, "Invalid buffer_size argument %zu",
                        buffer_size);
        goto error;
    }

    logmsg(DEBUG, "Using a 'slurp' buffer size of %zu bytes", buffer_size);

    obj_file = open_data_obj(session, rods_path, O_RDONLY, flags, error);
    if (error->code != 0) goto error;

    char *content = slurp_data_obj(session, obj_file, buffer_size, error);
    const int status = close_data_obj(session, obj_file);

    if (error->code != 0) goto error;
    if (status < 0) {
        char *err_subname;
        const char *err_name = rodsErrorName(status, &err_subname);
        set_baton_error(error, status,
                        "Failed to close data object: '%s' error %d %s",
                        rods_path->outPath, status, err_name);
        goto error;
    }

    free_data_obj(obj_file);

    return content;

error:
    if (obj_file) free_data_obj(obj_file);

    return NULL;
}

int redirect_for_get(baton_session_t *session, dataObjInp_t *obj_open_in, baton_error_t *error) {
    int status = 0;

    if (!session->redirect_host) {
        logmsg(DEBUG, "Checking for host redirection from '%s' to get '%s'",
            session->local_host, obj_open_in->objPath);

        if (obj_open_in->dataSize < REDIRECT_SIZE_THRESHOLD) {
            logmsg(DEBUG, "Not redirecting to get '%s' as it is smaller than "
                          "the redirect threshold (%d < %d)",
                   obj_open_in->objPath, obj_open_in->dataSize, REDIRECT_SIZE_THRESHOLD);
            return status;
        }

        status = rcGetHostForGet(session->conn, obj_open_in, &session->redirect_host);
        if (status < 0) {
            char *err_subname;
            const char *err_name = rodsErrorName(status, &err_subname);
            set_baton_error(error, status,
                            "Failed to choose host to get data object: '%s' error %d %s",
                            obj_open_in->objPath, status, err_name);
            return status;
        }

        if (session->redirect_host == NULL) {
            logmsg(DEBUG, "No host redirection from '%s' available for '%s'",
                session->local_host, obj_open_in->objPath);
            return status;
        }

        // iRODS is very sensitive to host naming and not good at detecting if a hostname
        // routes to itself. It doesn't handle "localhost" as a hostname, so if we want to
        // support that (which we do, for test instances), we need to check for that name
        // ourselves and avoid redirecting in that case.
        if (strcmp(session->redirect_host, "localhost") == 0) {
            logmsg(DEBUG, "Not redirecting from '%s' to put '%s' as it is localhost",
                session->local_host, obj_open_in->objPath);
            return status;
        }

        if (strcmp(session->redirect_host, session->local_host) == 0) {
            logmsg(DEBUG, "No host redirection from '%s'  to '%s' required for '%s'",
                session->local_host, session->redirect_host, obj_open_in->objPath);
            return status;
        }

        logmsg(INFO, "Redirecting from '%s' to '%s' to get '%s",
               session->local_host, session->redirect_host, obj_open_in->objPath);
        baton_disconnect(session);

        status = baton_reconnect(session);
        if (status < 0) {
            set_baton_error(error, status,
                            "Failed to reconnect to put '%s' error %d",
                            obj_open_in->objPath, status);
            return status;
        }
    }

    return status;
}

json_t *ingest_data_obj(baton_session_t *session, rodsPath_t *rods_path,
                        const option_flags flags, const size_t buffer_size,
                        baton_error_t *error) {
    char *content = NULL;

    init_baton_error(error);

    if (buffer_size == 0) {
        set_baton_error(error, -1, "Invalid buffer_size argument %zu",
                        buffer_size);
        goto error;
    }

    if (rods_path->objType != DATA_OBJ_T) {
        set_baton_error(error, USER_INPUT_PATH_ERR,
                        "Cannot read the contents of '%s' because "
                        "it is not a data object", rods_path->outPath);
        goto error;
    }

    json_t *results = list_path(session->conn, rods_path, flags, error);
    if (error->code != 0) goto error;

    content = do_slurp(session, rods_path, buffer_size, error);
    if (error->code != 0) goto error;

    if (content) {
        const size_t len = strlen(content);

        if (maybe_utf8(content, len)) {
            json_t *packed = json_pack("s", content);
            if (!packed) {
                set_baton_error(error, -1,
                                "Failed to pack the %zu byte contents "
                                "of '%s' as JSON", len, rods_path->outPath);
                goto error;
            }

            json_object_set_new(results, JSON_DATA_KEY, packed);
        }
        else {
            set_baton_error(error, USER_INPUT_PATH_ERR,
                            "The contents of '%s' cannot be encoded as UTF-8 "
                            "for JSON output", rods_path->outPath);
            goto error;
        }
        free(content);
    }

    return results;

error:
    if (content) free(content);

    return NULL;
}

data_obj_file_t *open_data_obj(baton_session_t *session, rodsPath_t *rods_path,
                               const int open_flag, const int flags,
                               baton_error_t *error) {
    data_obj_file_t *data_obj = NULL;

    int descriptor;

    init_baton_error(error);
    dataObjInp_t obj_open_in = {0};

    logmsg(DEBUG, "Opening data object '%s'", rods_path->outPath);
    snprintf(obj_open_in.objPath, MAX_NAME_LEN, "%s", rods_path->outPath);

    if (flags & WRITE_LOCK) {
      logmsg(DEBUG, "Enabling write lock for '%s'", rods_path->outPath);
      addKeyVal(&obj_open_in.condInput, LOCK_TYPE_KW, WRITE_LOCK_TYPE);
    }

    switch(open_flag) {
        case (O_RDONLY):
          obj_open_in.openFlags = O_RDONLY;

          descriptor = rcDataObjOpen(session->conn, &obj_open_in);
          break;

        case (O_WRONLY):
          obj_open_in.openFlags  = O_WRONLY;
          obj_open_in.createMode = 0750;
          obj_open_in.dataSize   = 0;
          addKeyVal(&obj_open_in.condInput, FORCE_FLAG_KW, "");
          descriptor = rcDataObjCreate(session->conn, &obj_open_in);
          clearKeyVal(&obj_open_in.condInput);
          break;

        default:
          set_baton_error(error, -1,
                          "Failed to open '%s': file open flag must be either"
                          "O_RDONLY or O_WRONLY", rods_path->outPath,
                          open_flag);
          goto error;
    }

    if (descriptor < 0) {
        char *err_subname;
        const char *err_name = rodsErrorName(descriptor, &err_subname);
        set_baton_error(error, descriptor,
                        "Failed to open '%s': error %d %s",
                        rods_path->outPath, descriptor, err_name);
        goto error;
    }

    data_obj = calloc(1, sizeof (data_obj_file_t));
    if (!data_obj) {
        logmsg(ERROR, "Failed to allocate memory: error %d %s",
               errno, strerror(errno));
        goto error;
    }

    data_obj->path                = rods_path->outPath;
    data_obj->flags               = obj_open_in.openFlags;
    data_obj->open_obj            = calloc(1, sizeof (openedDataObjInp_t));
    data_obj->open_obj->l1descInx = descriptor;
    data_obj->md5_last_read       = calloc(33, sizeof (char));
    data_obj->md5_last_write      = calloc(33, sizeof (char));

    return data_obj;

error:
    if (data_obj) free_data_obj(data_obj);

    return NULL;
}

int close_data_obj(baton_session_t *session, const data_obj_file_t *data_obj) {
    logmsg(DEBUG, "Closing '%s'", data_obj->path);
    const int status = rcDataObjClose(session->conn, data_obj->open_obj);

    return status;
}

void free_data_obj(data_obj_file_t *data_obj) {
    assert(data_obj);

    if (data_obj->open_obj)       free(data_obj->open_obj);
    if (data_obj->md5_last_read)  free(data_obj->md5_last_read);
    if (data_obj->md5_last_write) free(data_obj->md5_last_write);

    free(data_obj);
}

size_t read_chunk(rcComm_t *conn, const data_obj_file_t *data_obj, char *buffer,
                  const size_t len, baton_error_t *error) {
    init_baton_error(error);

    data_obj->open_obj->len = len;

    bytesBuf_t obj_read_out = {0};
    obj_read_out.buf = buffer;
    obj_read_out.len = len;

    logmsg(DEBUG, "Reading up to %zu bytes from '%s'", len, data_obj->path);

    int num_read = rcDataObjRead(conn, data_obj->open_obj, &obj_read_out);
    if (num_read < 0) {
        char *err_subname;
        const char *err_name = rodsErrorName(num_read, &err_subname);
        set_baton_error(error, num_read,
                        "Failed to read up to %zu bytes from '%s': %s",
                        len, data_obj->path, err_name);
        num_read = 0;
        goto finally;
    }

    logmsg(DEBUG, "Read %d bytes from '%s'", num_read, data_obj->path);

finally:
    return num_read;
}

size_t read_data_obj(baton_session_t *session, const data_obj_file_t *data_obj,
                     FILE *out, const size_t buffer_size, baton_error_t *error) {
    size_t num_read    = 0;
    size_t num_written = 0;
    char *buffer       = NULL;

    init_baton_error(error);

    if (buffer_size == 0) {
        set_baton_error(error, -1, "Invalid buffer_size argument %u",
                        buffer_size);
        goto finally;
    }

    buffer = calloc(buffer_size +1, sizeof (char));
    if (!buffer) {
        logmsg(ERROR, "Failed to allocate memory: error %d %s",
               errno, strerror(errno));
        goto finally;
    }

    unsigned char digest[16];
    EVP_MD_CTX *context = compat_MD5Init(error);
    if (error->code != 0) {
        logmsg(ERROR, error->message);
        goto finally;
    }
    
    size_t nr;
    while ((nr = read_chunk(session->conn, data_obj, buffer, buffer_size, error)) > 0) {
        num_read += nr;
        logmsg(DEBUG, "Writing %zu bytes from '%s' to stream",
               nr, data_obj->path);

        const int status = fwrite(buffer, 1, nr, out);
        if (status < 0) {
            logmsg(ERROR, "Failed to write to stream: error %d %s",
                   errno, strerror(errno));
            goto finally;
        }
        const size_t nw = nr;
        num_written += nw;

        compat_MD5Update(context, (unsigned char*) buffer, nr, error);
        if (error->code != 0) {
            logmsg(ERROR, error->message);
            goto finally;
        }
        memset(buffer, 0, buffer_size);
    }

    compat_MD5Final(digest, context, error);
    if (error->code != 0) {
        logmsg(ERROR, error->message);
        goto finally;
    }

    set_md5_last_read(data_obj, digest);

    if (num_read != num_written) {
        set_baton_error(error, -1, "Read %zu bytes from '%s' but wrote "
                        "%zu bytes ", num_read, data_obj->path, num_written);
        goto finally;
    }

    if (!validate_md5_last_read(session->conn, data_obj)) {
        logmsg(WARN, "Checksum mismatch for '%s' having MD5 %s on reading",
               data_obj->path, data_obj->md5_last_read);
    }

    logmsg(NOTICE, "Wrote %zu bytes from '%s' to stream having MD5 %s",
           num_written, data_obj->path, data_obj->md5_last_read);

finally:
    if (buffer) free(buffer);

    return num_written;
}

char *slurp_data_obj(baton_session_t *session, const data_obj_file_t *data_obj,
                     const size_t buffer_size, baton_error_t *error) {
    char *buffer  = NULL;
    char *content = NULL;

    init_baton_error(error);

    logmsg(DEBUG, "Using a transfer buffer size of %zu bytes", buffer_size);

    buffer = calloc(buffer_size +1, sizeof (char));
    if (!buffer) {
        logmsg(ERROR, "Failed to allocate memory: error %d %s",
               errno, strerror(errno));
        goto error;
    }

    unsigned char digest[16];
    EVP_MD_CTX *context = compat_MD5Init(error);
    if (error->code != 0) {
        logmsg(ERROR, error->message);
        goto error;
    }

    size_t capacity = buffer_size;
    size_t num_read = 0;

    content = calloc(capacity, sizeof (char));
    if (!content) {
        logmsg(ERROR, "Failed to allocate memory: error %d %s",
               errno, strerror(errno));
        goto error;
    }

    size_t nr;
    while ((nr = read_chunk(session->conn, data_obj, buffer, buffer_size, error)) > 0) {
      logmsg(TRACE, "Read %zu bytes. Capacity %zu, num read %zu",
             nr, capacity, num_read);
        if (num_read + nr > capacity) {
            capacity = capacity * 2;

            char *tmp = NULL;
            tmp = realloc(content, capacity);
            if (!tmp) {
                logmsg(ERROR, "Failed to allocate memory: error %d %s",
                       errno, strerror(errno));
                goto error;
            }

            memset(tmp + num_read, 0, capacity - num_read);
            content = tmp;
        }

        memcpy(content + num_read, buffer, nr);
        memset(buffer, 0, buffer_size);
        num_read += nr;
    }

    logmsg(DEBUG, "Final capacity %zu, offset %zu", capacity, num_read);

    compat_MD5Update(context, (unsigned char *) content, num_read, error);
    if (error->code != 0) {
        logmsg(ERROR, error->message);
        goto error;
    }

    compat_MD5Final(digest, context, error);
    if (error->code != 0) {
        logmsg(ERROR, error->message);
        goto error;
    }
    set_md5_last_read(data_obj, digest);

    if (!validate_md5_last_read(session->conn, data_obj)) {
        logmsg(WARN, "Checksum mismatch for '%s' having MD5 %s on reading",
               data_obj->path, data_obj->md5_last_read);
    }

    logmsg(NOTICE, "Wrote %zu bytes from '%s' to buffer having MD5 %s",
           num_read, data_obj->path, data_obj->md5_last_read);

    free(buffer);

    return content;

error:
    if (buffer)  free(buffer);
    if (content) free(content);

    return NULL;
}

int get_data_obj_file(baton_session_t *session, rodsPath_t *rods_path, const char *local_path,
                      option_flags flags, baton_error_t *error) {
    char *tmpname  = NULL;
    dataObjInp_t obj_get_in = {0};
    int status;

    init_baton_error(error);

    if (rods_path->objType != DATA_OBJ_T) {
        set_baton_error(error, USER_INPUT_PATH_ERR,
                        "Cannot get '%s' because "
                        "it is not a data object", rods_path->outPath);
        goto error;
    }

    obj_get_in.openFlags = O_RDONLY;

    logmsg(DEBUG, "Getting '%s'", rods_path->outPath);
    snprintf(obj_get_in.objPath, MAX_NAME_LEN, "%s", rods_path->outPath);

    if (flags & VERIFY_CHECKSUM) {
        logmsg(DEBUG, "Will verify the checksum of '%s' after get", local_path);
        addKeyVal(&obj_get_in.condInput, VERIFY_CHKSUM_KW, "");
    }

    if (flags & FORCE) {
        logmsg(DEBUG, "Will force overwrite '%s' if necessary", local_path);
        addKeyVal(&obj_get_in.condInput, FORCE_FLAG_KW, "");
    }

    tmpname = copy_str(local_path, MAX_STR_LEN);
    if (!tmpname) goto error;

    rodsObjStat_t stat = {0};
    rodsObjStat_t *stat_ptr = &stat;
    status = rcObjStat(session->conn, &obj_get_in, &stat_ptr);
    if (status < 0) {
        char *err_subname;
        const char *err_name = rodsErrorName(status, &err_subname);
        set_baton_error(error, status,
                        "Failed to stat data object: '%s' to '%s', error %d %s",
                        rods_path->outPath, local_path, status, err_name);
        goto error;
    }
    obj_get_in.dataSize = stat_ptr->objSize;

    logmsg(DEBUG, "Size of '%s' is %d", obj_get_in.objPath, obj_get_in.dataSize);

    if (redirect_for_get(session, &obj_get_in, error)) goto error;

    status = rcDataObjGet(session->conn, &obj_get_in, tmpname);
    if (status < 0) {
        char *err_subname;
        const char *err_name = rodsErrorName(status, &err_subname);
        set_baton_error(error, status,
                        "Failed to get data object: '%s' to '%s', error %d %s",
                        rods_path->outPath, local_path, status, err_name);
        goto error;
    }
    logmsg(NOTICE, "Get of '%s' to '%s' completed", rods_path->outPath, local_path);

    free(tmpname);

    return error->code;

error:
    if (tmpname) free(tmpname);

    return error->code;
}

int get_data_obj_stream(baton_session_t *session, rodsPath_t *rods_path, FILE *out,
                        const size_t buffer_size, baton_error_t *error) {
    data_obj_file_t *data_obj = NULL;
    const int           flags = 0;

    init_baton_error(error);

    if (buffer_size == 0) {
        set_baton_error(error, -1, "Invalid buffer_size argument %zu",
                        buffer_size);
        goto error;
    }

    logmsg(DEBUG, "Writing '%s' to a stream", rods_path->outPath);

    if (rods_path->objType != DATA_OBJ_T) {
        set_baton_error(error, USER_INPUT_PATH_ERR,
                        "Cannot write the contents of '%s' because "
                        "it is not a data object", rods_path->outPath);
        goto error;
    }

    data_obj = open_data_obj(session, rods_path, O_RDONLY, flags, error);
    if (error->code != 0) goto error;

    const size_t nr = read_data_obj(session, data_obj, out, buffer_size, error);
    const int status = close_data_obj(session, data_obj);

    if (error->code != 0) goto error;
    if (status < 0) {
        char *err_subname;
        const char *err_name = rodsErrorName(status, &err_subname);
        set_baton_error(error, status,
                        "Failed to close data object: '%s' error %d %s",
                        rods_path->outPath, status, err_name);
        goto error;
    }

    free_data_obj(data_obj);

    return nr;

error:
    if (data_obj) free_data_obj(data_obj);

    return error->code;
}

char *checksum_data_obj(rcComm_t *conn, rodsPath_t *rods_path,
                        option_flags flags, baton_error_t *error) {
    char *checksum = NULL;
    dataObjInp_t obj_chk_in = {0};

    init_baton_error(error);

    obj_chk_in.openFlags = O_RDONLY;

    if (rods_path->objState == NOT_EXIST_ST) {
        set_baton_error(error, USER_FILE_DOES_NOT_EXIST,
                        "Path '%s' does not exist "
                        "(or lacks access permission)", rods_path->outPath);
        goto error;
    }

    switch (rods_path->objType) {
        case DATA_OBJ_T:
            logmsg(TRACE, "Identified '%s' as a data object",
                   rods_path->outPath);
            snprintf(obj_chk_in.objPath, MAX_NAME_LEN, "%s",
                     rods_path->outPath);
            break;

        case COLL_OBJ_T:
            logmsg(TRACE, "Identified '%s' as a collection",
                   rods_path->outPath);
            set_baton_error(error, USER_INPUT_PATH_ERR,
                            "Failed to list checksum of '%s' as it is "
                            "a collection", rods_path->outPath);
            goto error;

        default:
            set_baton_error(error, USER_INPUT_PATH_ERR,
                            "Failed to list checksum of '%s' as it is "
                            "neither data object nor collection",
                            rods_path->outPath);
            goto error;
    }

    if (!(flags & VERIFY_CHECKSUM) && !(flags & CALCULATE_CHECKSUM)) {
        logmsg(DEBUG, "No checksum operation specified for '%s', defaulting "
	       "to calculating a checksum",  rods_path->outPath);
        flags = flags | CALCULATE_CHECKSUM;
    }
    else if ((flags & VERIFY_CHECKSUM) && (flags & CALCULATE_CHECKSUM)) {
        set_baton_error(error, USER_INPUT_OPTION_ERR,
                        "Cannot both verify and update the checksum "
                        "of data object '%s' ", rods_path->outPath);
        goto error;
    }

    if (flags & VERIFY_CHECKSUM) {
        logmsg(DEBUG, "Verifying checksums of all replicates "
               "of data object '%s'", rods_path->outPath);
        // This operates on all replicas without requiring CHKSUM_ALL_KW
        addKeyVal(&obj_chk_in.condInput, VERIFY_CHKSUM_KW, "");
    }
    else if (flags & CALCULATE_CHECKSUM) {
        logmsg(DEBUG, "Calculating checksums of all replicates "
               "of data object '%s'", rods_path->outPath);
        addKeyVal(&obj_chk_in.condInput, CHKSUM_ALL_KW, "");

        if (flags & FORCE) {
            logmsg(DEBUG, "Forcing checksum recaclulation "
                   "of data object '%s'", rods_path->outPath);
            addKeyVal(&obj_chk_in.condInput, FORCE_CHKSUM_KW, "");
        }
    }

    const int status = rcDataObjChksum(conn, &obj_chk_in, &checksum);
    clearKeyVal(&obj_chk_in.condInput);

    if (status < 0) {
        char *err_subname;
        const char *err_name = rodsErrorName(status, &err_subname);
        set_baton_error(error, status,
                        "Failed to list checksum of '%s': %d %s",
                        rods_path->outPath, status, err_name);
        goto error;
    }

    return checksum;

error:
    if (checksum) free(checksum);

    return NULL;
}

void set_md5_last_read(const data_obj_file_t *data_obj, unsigned char digest[16]) {
    char *md5 = data_obj->md5_last_read;
    for (int i = 0; i < 16; i++) {
        snprintf(md5 + i * 2, 3, "%02x", digest[i]);
    }
}

int validate_md5_last_read(rcComm_t *conn, const data_obj_file_t *data_obj) {
    dataObjInp_t obj_md5_in = {0};

    snprintf(obj_md5_in.objPath, MAX_NAME_LEN, "%s", data_obj->path);

    char *md5 = NULL;
    int status = rcDataObjChksum(conn, &obj_md5_in, &md5);
    if (status < 0) goto finally;

    logmsg(DEBUG, "Comparing last read MD5 of '%s' with expected MD5 of '%s'",
           data_obj->md5_last_read, md5);

    status = str_equals_ignore_case(data_obj->md5_last_read, md5, 32);

finally:
    if (md5) free(md5);

    return status;
}
