/**
 * Copyright (C) 2013, 2014, 2019, 2025 Genome Research Ltd. All rights
 * reserved.
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
 * @file utilities.h
 * @author Keith James <kdj@sanger.ac.uk>
 */

#ifndef _BATON_UTILITIES_H
#define _BATON_UTILITIES_H

#include <stdio.h>

#include "error.h"

#define MAX_STR_LEN (1024 * 1024 * 1024)

#define ISO8601_FORMAT "%Y-%m-%dT%H:%M:%S"
#define RFC3339_FORMAT "%Y-%m-%dT%H:%M:%SZ"

int str_starts_with(const char *str, const char *prefix, size_t max_len);

int str_ends_with(const char *str, const char *suffix, size_t max_len);

int str_equals(const char *str1, const char *str2, size_t max_len);

int str_equals_ignore_case(const char *str1, const char *str2, size_t max_len);

char* copy_str(const char *str, size_t max_len);


int check_str_arg(const char *arg_name,
                  const char *arg_value,
                  size_t arg_size,
                  baton_error_t *error);

int check_str_arg_permit_empty(const char *arg_name,
                               const char *arg_value,
                               size_t arg_size,
                               baton_error_t *error);

const char* parse_base_name(const char *path);

char* parse_zone_name(const char *path);

size_t parse_size(const char *str);

FILE* maybe_stdin(const char *path);

char* format_timestamp(const char *raw_timestamp, const char *format);

char* parse_timestamp(const char *timestamp, const char *format);

int maybe_utf8(const char *str, size_t max_len);

size_t to_utf8(const char *input, char *output, size_t max_len);

#endif // _BATON_UTILITIES_H