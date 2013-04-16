#ifndef  __RAD_OPTS_H__
#define __RAD_OPTS_H__

#include "src/providers/data_provider.h"

/**
 *  Default values for radius provider options.
 */
struct dp_option default_rad_options[] = {
    { "rad_server", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "rad_port", DP_OPT_NUMBER, { .number = 1812 }, NULL_NUMBER },
    { "rad_tmp", DP_OPT_BOOL, BOOL_TRUE, BOOL_TRUE },
    DP_OPTION_TERMINATOR
};

#endif /* __RAD_OPTS_H__ */
