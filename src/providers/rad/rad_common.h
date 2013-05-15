/*
    SSSD

    RADIUS Backend module - common header file

    Authors:
        Ondrej Hujnak <xhujna00@stud.fit.vutbr.cz>

    Copyright (C) 2013 Ondrej Hujnak

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __RAD_COMMON_H__
#define __RAD_COMMON_H__

#include "util/util.h"
#include "providers/dp_backend.h"

/**
 *  List of all options for radius provider.
 */
enum rad_opts {
    RAD_SERVER,
    RAD_PORT,
    RAD_SECRET,
    RAD_TIMEOUT,
    RAD_CONN_RETRIES,
    RAD_IDENTIFIER,

    RAD_OPTS  /* holds number of possible options */
};

/**
 * Context of RADIUS provider
 */
struct rad_ctx {
    struct dp_option *opts;
};

/* rad_init.c */

/**
 * Handles provider initialization.
 *
 * @var bectx is context of whole domain provider
 * @var ops is used to register request handlers
 * @var pvt_auth_data is used to store context
 */
int sssm_rad_auth_init(struct be_ctx *bectx,
                       struct bet_ops **ops,
                       void **pvt_auth_data);

/* rad_common.c */

/**
 * Loads options for radius provider.
 *
 * @var memctx is parent node in talloc hierarchy
 * @var cdb is context of configuration database
 * @var conf_path is path to config file
 * @var _opts is used to return loaded options
 */
errno_t rad_get_options(TALLOC_CTX *memctx,
                        struct confdb_ctx *cdb,
                        const char *conf_path,
                        struct dp_option **_opts);


#endif  /* __RAD_COMMON_H__ */
