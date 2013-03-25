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
  RAD_TMP,  // just temporary for development purposes

  RAD_OPTS  // holds number of possible options
};

/**
 * Loads options for radius provider.
 */
errno_t rad_get_options( TALLOC_CTX *memctx,
                         struct confdb_ctx *cdb,
                         const char *conf_path,
                         struct dp_option **_opts);

int sssm_rad_auth_init( struct be_ctx *bectx,
                        struct bet_ops **ops,
                        void **pvt_auth_data);

#endif  /* __RAD_COMMON_H__ */
