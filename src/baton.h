/**
 * Copyright (C) 2013, 2014, 2015, 2016, 2017, 2025 Genome Research
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
 * @file baton.h
 * @author Keith James <kdj@sanger.ac.uk>
 * @author Joshua C. Randall <jcrandall@alum.mit.edu>
 */

#ifndef _BATON_H
#define _BATON_H

#include <rodsClient.h>

#include "json_query.h"

#define MAX_VERSION_STR_LEN 512

#define MAX_CLIENT_NAME_LEN 512

#define DEFAULT_MAX_CONNECT_TIME 600

#define META_ADD_NAME "add"
#define META_REM_NAME "rm"

#define FILE_SIZE_UNITS "KB"


/**
 *  @enum metadata_op
 *  @brief AVU metadata operations.
 */
typedef enum {
    /** Add an AVU. */
    META_ADD,
    /** Remove an AVU. */
    META_REM
} metadata_op;

typedef enum {
    /** Non-recursive operation */
    NO_RECURSE,
    /** Recursive operation */
    RECURSE
} recursive_op;

typedef enum {
    /** Print AVUs on collections and data objects */
    PRINT_AVU          = 1 << 0,
    /** Print ACLs on collections and data objects */
    PRINT_ACL          = 1 << 1,
    /** Print the contents of collections */
    PRINT_CONTENTS     = 1 << 2,
    /** Print timestamps on collections and data objects */
    PRINT_TIMESTAMP    = 1 << 3,
    /** Print file sizes for data objects */
    PRINT_SIZE         = 1 << 4,
    /** Pretty-print JSON */
    PRINT_PRETTY       = 1 << 5,
    /** Print raw output */
    PRINT_RAW          = 1 << 6,
    /** Search collection AVUs */
    SEARCH_COLLECTIONS = 1 << 7,
    /** Search data object AVUs */
    SEARCH_OBJECTS     = 1 << 8,
    /** Unsafely resolve relative paths */
    UNSAFE_RESOLVE     = 1 << 9,
    /** Print replicate details for data objects */
    PRINT_REPLICATE    = 1 << 10,
    /** Print checksums for data objects */
    PRINT_CHECKSUM     = 1 << 11,
    /** Calculate checksums for data objects */
    CALCULATE_CHECKSUM = 1 << 12,
    /** Verify checksums for data objects */
    VERIFY_CHECKSUM    = 1 << 13,
    /** Add an AVU */
    ADD_AVU            = 1 << 14,
    /** Remove an AVU */
    REMOVE_AVU         = 1 << 15,
    /** Recursive operation on collections */
    RECURSIVE          = 1 << 16,
    /** Save files */
    SAVE_FILES         = 1 << 17,
    /** Flush output */
    FLUSH              = 1 << 18,
    /** Force an operation */
    FORCE              = 1 << 19,
    /** Avoid any operations that contact servers other than rodshost */
    SINGLE_SERVER      = 1 << 20,
    /** Use advisory write lock on server */
    WRITE_LOCK         = 1 << 21
} option_flags;


/**
 *  @struct metadata_op
 *  @brief AVU metadata operation inputs.
 */
typedef struct mod_metadata_in {
    /** The operation to perform. */
    metadata_op op;
    /** The type argument for the iRODS path i.e. -d or -C. */
    char *type_arg;
    /** The resolved iRODS path. */
    rodsPath_t *rods_path;
    /** The AVU attribute name. */
    char *attr_name;
    /** The AVU attribute value. */
    char *attr_value;
    /** The AVU attribute units. */
    char *attr_units;
} mod_metadata_in_t;

/**
 * @struct baton_session
 * @brief The baton session for communicating with iRODS.
 */
typedef struct baton_session {
    char* redirect_host;
    long max_connect_time;
    int reconnect_flag;
    rodsEnv *env;
    rcComm_t *conn;
} baton_session_t;


/**
 * Allocates a new baton session.
 *
 * @return A pointer to a newly created baton session structure.
 *         Returns NULL if the session could not be created.
 */
baton_session_t *new_baton_session(void);

/**
 * Frees the memory allocated for a baton session.
 *
 * @param session A pointer to the baton_session_t session to be freed.
 *                If the pointer is null, the function does nothing.
 */
void free_baton_session(baton_session_t *session);

/**
 * Test that a connection can be made to the server.
 *
 * @return 1 on success, 0 on failure.
 */
int is_irods_available(void);

/**
 * Set the SP_OPTION environment variable so that the 'ips' command
 * knows the name of a client program.
 *
 * @param[in] name The client name.
 *
 * @return The return value of 'setenv'.
 */
int declare_client_name(const char *name);

/**
 * Return a newly allocated "dotted-triple" iRODS version string of
 * the client. The caller is responsible for freeing the string.
 *
 * @return A version string.
 */
char* get_client_version(void);

/**
 * Return a newly allocated "dotted-triple" iRODS version string of the
 * server. The caller is responsible for freeing the string.
 *
 * @param[in]  conn         An open iRODS connection.
 * @param[out] error        An error report struct.
 *
 * @return A version string.
 */
char* get_server_version(rcComm_t *conn, baton_error_t *error);

int baton_connect(baton_session_t *session);

void baton_disconnect(baton_session_t *session);

/**
 * Initialise an iRODS path by copying a string into its inPath.
 *
 * @param[out] rods_path An iRODS path.
 * @param[in]  in_path    A string representing an unresolved iRODS path.
 *
 * @return 0 on success, -1 on failure.
 */
int init_rods_path(rodsPath_t *rods_path, const char *in_path);

/**
 * Initialise and resolve an iRODS path by copying a string into its
 * inPath, parsing it and resolving it on the server.
 *
 * @param[in]  session      An open baton session.
 * @param[out] rods_path    An iRODS path.
 * @param[in]  in_path      A string representing an unresolved iRODS path.
 * @param[in]  flags        Function behaviour options.
 * @param[out] error        An error report struct.
 *
 * @return 0 on success, iRODS error code on failure.
 */
int resolve_rods_path(baton_session_t *session,
                      rodsPath_t *rods_path, const char *in_path, option_flags flags,
                      baton_error_t *error);

/**
 * Initialise and set an iRODS path by copying a string into both its
 * inPath and outPath and then resolving it on the server. The path is not
 * parsed, so must be derived from an existing parsed path.
 *
 * @param[in]  session      An open baton session.
 * @param[in]  path      A string representing an unresolved iRODS path.
 * @param[out] error     An error report struct.
 *
 * @return 0 on success, iRODS error code on failure.
 */
int set_rods_path(rcComm_t *conn, rodsPath_t *rods_path, char *path,
                  baton_error_t *error);

int move_rods_path(rcComm_t *conn, rodsPath_t *rods_path, char *new_path,
                   baton_error_t *error);

int resolve_collection(baton_session_t *session, json_t *object,
                       option_flags flags, baton_error_t *error);

/**
 * Search metadata to find matching data objects and collections.
 *
 * @param[in]  conn         An open iRODS connection.
 * @param[in]  query        A JSON query specification which includes the
 *                          attribute name and value to match. It may also have
 *                          an iRODS path to limit search scope. Only results
 *                          under this path will be returned. Omitting the path
 *                          means the search will be global.
 * @param[in]  zone_name    An iRODS zone name. Optional, NULL means the current
 *                          zone.
 * @param[in]  flags        Search behaviour options.
 * @param[out] error        An error report struct.
 *
 * @return A newly constructed JSON array of JSON result objects.
 */
json_t *search_metadata(rcComm_t *conn, json_t *query, char *zone_name,
                        option_flags flags, baton_error_t *error);

/**
 * Perform a specific query (SQL must have been installed on iRODS server by an
 * administrator using `iadmin asq`).
 *
 * @param[in]  conn         An open iRODS connection.
 * @param[in]  query        A JSON query specification which includes the
 *                          SQL query and optionally input arguments and output
 *                          labels.
 * @param[in]  zone_name    An iRODS zone name. Optional, NULL means the current
 *                          zone.
 * @param[out] error        An error report struct.
 *
 * @return A newly constructed JSON array of JSON result objects.
 */
json_t *search_specific(rcComm_t *conn, const json_t *query, char *zone_name,
                        baton_error_t *error);

/**
 * Modify the access control list of a resolved iRODS path.
 *
 * @param[in]     conn       An open iRODS connection.
 * @param[out]    rods_path  An iRODS path.
 * @param[in]     recurse    Recurse into collections, one of RECURSE,
                             NO_RECURSE.
 * @param[in] user_with_zone The user name with zone i.e <user name>#<zone name>.
 * @param[in]     perms      An iRODS access control mode (read, write etc.)
 * @param[in,out] error      An error report struct.
 *
 * @return 0 on success, iRODS error code on failure.
 */
int modify_permissions(rcComm_t *conn, rodsPath_t *rods_path,
                       recursive_op recurse, char *user_with_zone,
                       char *perms,  baton_error_t *error);

/**
 * Modify the access control list of a resolved iRODS path.  The
 * functionality is identical to modify_permission, except that the
 * access control argument is a JSON struct.
 *
 * @param[in]  conn        An open iRODS connection.
 * @param[out] rods_path   An iRODS path.
 * @param[in]  recurse     Recurse into collections, one of RECURSE, NO_RECURSE.
 * @param[in]  acl         A JSON access control object.
 * @param[out] error       An error report struct.
 *
 * @return 0 on success, iRODS error code on failure.
 */
int modify_json_permissions(rcComm_t *conn, rodsPath_t *rods_path,
                            recursive_op recurse, const json_t *acl,
                            baton_error_t *error);

/**
 * Apply a metadata operation to an AVU on a resolved iRODS path.
 *
 * @param[in]     conn         An open iRODS connection.
 * @param[in]     rods_path    A resolved iRODS path.
 * @param[in]     op           An operation to apply e.g. ADD, REMOVE.
 * @param[in]     attr_name    The attribute name.
 * @param[in]     attr_value   The attribute value.
 * @param[in]     attr_units   The attribute unit (the empty string for none).
 * @param[in,out] error        An error report struct.
 *
 * @return 0 on success, iRODS error code on failure.
 */
int modify_metadata(rcComm_t *conn, rodsPath_t *rods_path, metadata_op op,
                    char *attr_name, char *attr_value, char *attr_units,
                    baton_error_t *error);

/**
 * Apply a metadata operation to an AVU on a resolved iRODS path. The
 * functionality is identical to modify_metadata, except that the AVU is
 * a JSON struct argument, with optional units.
 *
 * @param[in]  conn        An open iRODS connection.
 * @param[in]  rods_path   A resolved iRODS path.
 * @param[in]  op          An operation to apply e.g. ADD, REMOVE.
 * @param[in]  avu         The JSON AVU.
 * @param[out] error       An error report struct.
 *
 * @return 0 on success, iRODS error code on failure.
 * @ref modify_metadata
 */
int modify_json_metadata(rcComm_t *conn, rodsPath_t *rods_path,
                         metadata_op op, const json_t *avu,
                         baton_error_t *error);

/**
 * Apply a metadata operation to a AVUs on a resolved iRODS path. The
 * operation is applied to each candidate AVU that does not occur in
 * reference AVUs.
 *
 * @param[in]  conn            An open iRODS connection.
 * @param[in]  rods_path       A resolved iRODS path.
 * @param[in]  op              An operation to apply to candidate AVUs
                               e.g. ADD, REMOVE.
 * @param[in]  candidate_avus  An JSON array of JSON AVUs.
 * @param[in]  reference_avus  An JSON array of JSON AVUs.
 * @param[out] error           An error report struct.
 *
 * @return 0 on success, iRODS error code on failure.
 * @ref modify_metadata
 */
int maybe_modify_json_metadata(rcComm_t *conn, rodsPath_t *rods_path,
                               metadata_op op,
                               const json_t *candidate_avus, json_t *reference_avus,
                               baton_error_t *error);

#endif // _BATON_H
