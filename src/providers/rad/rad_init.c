
#include "providers/rad/rad_auth.h"
#include "providers/rad/rad_common.h"

/**
 * Holds options and CTX for future use.
 */
struct rad_options {
  struct dp_option *opts;
  struct be_ctx *ctx;
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
 * Initialize Radius provider
 */
int sssm_rad_auth_init( struct be_ctx *bectx, struct bet_ops **ops, 
                        void **pvt_auth_data)
{
  int retval = EINVAL;
  struct be_ctx *ctx;

  if (rad_options == NULL) {
    rad_options = talloc_zero(bectx, struct rad_options);
    if (rad_options == NULL) {
      DEBUG(1, ("talloc_zero failed.\n"));
      return ENOMEM;
    }
    retval = rad_get_options(rad_options, bectx->cdb, bectx->conf_path,
                             &rad_options->opts);
    if (retval != EOK) {
      DEBUG(1, ("rad_get_options failed.\n"));
      return retval;
    }
  }

  ctx = bectx;

  *ops = &rad_auth_ops;
  *pvt_auth_data = ctx;
  
  return retval;
}
