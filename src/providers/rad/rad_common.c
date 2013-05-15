/*
    SSSD

    RADIUS Backend module - common functions

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

#include <unistd.h>

#include "providers/dp_backend.h"
#include "providers/rad/rad_common.h"
#include "providers/rad/rad_opts.h"

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
                        struct dp_option **_opts)
{
    int retval = EINVAL;
    struct dp_option *opts;
    char hostname[HOST_NAME_MAX+1];

    opts = talloc_zero(memctx, struct dp_option);
    if (opts == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_zero failed.\n"));
        return ENOMEM;
    }

    retval = dp_get_options(opts, cdb, conf_path, default_rad_options, RAD_OPTS, &opts);
    if (retval != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, ("dp_get_options failed.\n"));
        talloc_zfree(opts);
    } else if (dp_opt_get_string(opts, RAD_SERVER) == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, ("rad_server must be set!.\n"));
        talloc_zfree(opts);
    } else {
        if ((dp_opt_get_string(opts, RAD_IDENTIFIER) == NULL)
            && (gethostname(hostname, sizeof(hostname)) == 0)) {

            dp_opt_set_string(opts, RAD_IDENTIFIER, hostname);
        }
        *_opts = opts;
    }
  
    return retval;
}
