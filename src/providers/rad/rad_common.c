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

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

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
        DEBUG(SSSDBG_FATAL_FAILURE, ("dp_get_options failed.\n"));
        talloc_zfree(opts);
    } else if (dp_opt_get_string(opts, RAD_SERVER) == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, ("rad_server must be set!.\n"));
        talloc_zfree(opts);
    } else {
        *_opts = opts;
    }
  
    return retval;
}

int rad_send_req( struct rad_ctx *ctx,
                  const char *username,
                  const char *pass)
{
    int retval = EOK;
    int sockfd, retries, max_retries;
    struct sockaddr_in6 bind_addr;
    struct addrinfo hints, *res;
    struct timeval timeout;
    fd_set readfds;

    sockfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (sockfd < 0) {
        DEBUG(SSSDBG_OP_FAILURE, ("Could not initialize socket.\n"));
        return ERR_AUTH_FAILED;
    }

    memset((char *)&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin6_family = AF_INET6;
    bind_addr.sin6_addr = in6addr_any;
    bind_addr.sin6_port = htons((unsigned short) 0);

    if (bind(sockfd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        DEBUG(SSSDBG_OP_FAILURE, ("Could not bind socket.\n"));
        close(sockfd);
        return ERR_AUTH_FAILED;
    }

    memset((char *)&hints, 0, sizeof(hints));
    hints.ai_family = PF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    if ( getaddrinfo( dp_opt_get_string(ctx->opts, RAD_SERVER),
                      dp_opt_get_string(ctx->opts, RAD_PORT),
                      &hints,
                      &res) != 0) {
        DEBUG(SSSDBG_OP_FAILURE, ("Could not resolve server hostname.\n"));
        close(sockfd);
        return ERR_AUTH_FAILED;
    }

    for ( ; res != NULL; res = res->ai_next) {
        if (connect(sockfd, res->ai_addr, res->ai_addrlen) != -1)
            break;
    }
    if (res == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("Could not connect to server.\n"));
        close(sockfd);
        return ERR_AUTH_FAILED;
    }

    retries = 0;
    max_retries = dp_opt_get_int(ctx->opts, RAD_CONN_RETRIES);
    for (;;) {
        sendto(sockfd, "test", 4, 0, res->ai_addr, res->ai_addrlen);

        timeout.tv_usec = 0L;
        timeout.tv_sec = (long) dp_opt_get_int(ctx->opts, RAD_TIMEOUT);
        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);

        if (select(sockfd + 1, &readfds, NULL, NULL, &timeout) < 0) {
            if (errno == EINTR)
                continue;
            DEBUG(SSSDBG_OP_FAILURE, ("Could not connect to server.\n"));
            close(sockfd);
            return ERR_AUTH_FAILED;
        }
        if (FD_ISSET(sockfd, &readfds))
            break;

        if (++retries > max_retries) {
            DEBUG(SSSDBG_OP_FAILURE, ("Server do not respond [timeout].\n"));
            close(sockfd);
            return ERR_AUTH_FAILED; 
        }
    }

    return retval;
}
