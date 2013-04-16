
#include "providers/dp_backend.h"
#include "providers/rad/rad_common.h"
#include "providers/rad/rad_opts.h"

/**
 * Loads options for radius provider.
 */
errno_t rad_get_options( TALLOC_CTX *memctx,
                         struct confdb_ctx *cdb,
                         const char *conf_path,
                         struct dp_option **_opts)
{
    int retval = EINVAL;
    struct dp_option *opts;

    opts = talloc_zero(memctx, struct dp_option);
    if (opts == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("talloc_zero failed.\n"));
        return ENOMEM;
    }

    retval = dp_get_options(opts, cdb, conf_path, default_rad_options, RAD_OPTS, &opts);
    if (retval != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("dp_get_options failed.\n"));
        talloc_zfree(opts);
    } else {
        *_opts = opts;
    }
  
    return retval;
}
