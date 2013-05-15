/*
    SSSD

    RADIUS Backend module - initialization

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

#include "providers/rad/rad_auth.h"
#include "providers/rad/rad_common.h"

/**
 * Holds options and CTX for future use.
 */
struct rad_options {
    struct dp_option *opts;
    struct rad_ctx *ctx;
};
struct rad_options *rad_options = NULL;

/**
 * Used to set handler for sssd action
 */
struct bet_ops rad_auth_ops = {
    .handler = rad_auth_handler,
    .finalize = NULL
};

/**
 * Handles provider initialization.
 *
 * @var bectx is context of whole domain provider
 * @var ops is used to register request handlers
 * @var pvt_auth_data is used to store context
 */
int sssm_rad_auth_init(struct be_ctx *bectx, struct bet_ops **ops, 
                       void **pvt_auth_data)
{
    int retval = EINVAL;
    struct rad_ctx *ctx;

    if (rad_options == NULL) {
        rad_options = talloc_zero(bectx, struct rad_options);
        if (rad_options == NULL) {
            DEBUG(SSSDBG_FATAL_FAILURE, ("talloc_zero failed.\n"));
            return ENOMEM;
        }
        retval = rad_get_options(rad_options, bectx->cdb, bectx->conf_path,
                                 &rad_options->opts);
        if (retval != EOK) {
            DEBUG(SSSDBG_FATAL_FAILURE, ("rad_get_options failed.\n"));
            return retval;
        }
    }

    if (rad_options->ctx != NULL) {
        *ops = &rad_auth_ops;
        *pvt_auth_data = rad_options->ctx;
        return EOK;
    }

    ctx = talloc_zero(bectx, struct rad_ctx);
    if (!ctx) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_zero failed.\n"));
        return ENOMEM;
    };
    rad_options->ctx = ctx;

    ctx->opts = rad_options->opts;

    *ops = &rad_auth_ops;
    *pvt_auth_data = ctx;

    return retval;
}
