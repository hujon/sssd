/*
    SSSD

    RADIUS Backend module - header file with default options

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

#ifndef  __RAD_OPTS_H__
#define __RAD_OPTS_H__

#include "src/providers/data_provider.h"

/**
 *  Default values for radius provider options.
 */
struct dp_option default_rad_options[] = {
    { "rad_server", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "rad_port", DP_OPT_STRING, { "radius" }, NULL_STRING },
    { "rad_timeout", DP_OPT_NUMBER, { .number = 3 }, NULL_NUMBER},
    { "rad_conn_retries", DP_OPT_NUMBER, { .number = 2 }, NULL_NUMBER},
    { "rad_tmp", DP_OPT_BOOL, BOOL_TRUE, BOOL_TRUE },
    DP_OPTION_TERMINATOR
};

#endif /* __RAD_OPTS_H__ */
