/*
    SSSD

    RADIUS Backend module - auth file

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

#include <krad.h>
#include <security/pam_modules.h>

#include "providers/dp_backend.h"
#include "providers/rad/rad_auth.h"
#include "providers/rad/rad_common.h"

struct rad_req {
    struct rad_ctx *rad_ctx;
    struct pam_data *pd;
    struct be_req *be_req;

    krb5_context kctx;
    krad_attrset *attrs;
    krad_client *client;
    verto_ctx *vctx;
};

void rad_req_free(struct rad_req *req)
{
    if (req->attrs != NULL)
        krad_attrset_free(req->attrs);
    if (req->client != NULL)
        krad_client_free(req->client);
    if (req->vctx != NULL)
        verto_free(req->vctx);
    if (req->kctx != NULL)
        krb5_free_context(req->kctx);
}

static struct rad_ctx *get_rad_ctx(struct be_req *be_req)
{
    struct be_ctx *be_ctx = be_req_get_be_ctx(be_req);
    struct pam_data *pd;

    pd = talloc_get_type(be_req_get_data(be_req), struct pam_data);

    switch (pd->cmd) {
    case SSS_PAM_AUTHENTICATE:
    case SSS_CMD_RENEW:
        return talloc_get_type(be_ctx->bet_info[BET_AUTH].pvt_bet_data,
                              struct rad_ctx);
        break;
    default:
        DEBUG(SSSDBG_OP_FAILURE, ("Unsupported PAM task.\n"));
        return NULL;
    }
}

static inline krb5_data string2data(char *str)
{
    krb5_data d;

    d.magic = KV5M_DATA;
    d.data = str;
    d.length = strlen(str);

    return d;
}

static void rad_auth_done(krb5_error_code retval,
                          const krad_packet *req,
                          const krad_packet *response,
                          void *data);

static int rad_auth_send(struct rad_ctx *ctx,
                         struct pam_data *pd,
                         struct be_req *be_req)
{
    int retval = EOK;
    const char *pass = NULL;
    krb5_data tmp;
    krb5_error_code kerr;
    struct rad_req *rad_req;

    rad_req = talloc_zero(be_req, struct rad_req);
    if (rad_req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("talloc_zero failed.\n"));
        retval = ENOMEM;
        goto done;
    }
    rad_req->rad_ctx = ctx;
    rad_req->pd = pd;
    rad_req->be_req = be_req;

    kerr = krb5_init_context(&rad_req->kctx);
    if (kerr != 0) {
        DEBUG(SSSDBG_OP_FAILURE, ("Could not initialize KRB5 context.\n"));
        rad_req->kctx = NULL;
        retval = ERR_AUTH_FAILED;
        goto done;
    }
 
    rad_req->vctx = verto_default(NULL, VERTO_EV_TYPE_IO | VERTO_EV_TYPE_TIMEOUT);
    if (rad_req->vctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("Verto context initialization failed.\n"));
        retval = ERR_AUTH_FAILED;
        goto done;
    }
    
    kerr = krad_client_new(rad_req->kctx, rad_req->vctx, &rad_req->client);
    if (kerr != 0) {
        DEBUG(SSSDBG_OP_FAILURE, ("Could not initialize radius client.\n"));
        rad_req->client = NULL;
        retval = ERR_AUTH_FAILED;
        goto done;
    }
    
    kerr = krad_attrset_new(rad_req->kctx, &rad_req->attrs);
    if (kerr != 0) {
        DEBUG(SSSDBG_OP_FAILURE, ("Could not initialize attribute list.\n"));
        rad_req->attrs = NULL;
        retval = ERR_AUTH_FAILED;
        goto done;
    }
    tmp = string2data(pd->user);
    kerr = krad_attrset_add(rad_req->attrs,
                            krad_attr_name2num("User-Name"),
                            &tmp);
    if (kerr != 0) {
        DEBUG(SSSDBG_OP_FAILURE, ("Could not add User-Name to attribute list.\n"));
        goto done;
    }
    if (sss_authtok_get_password(pd->authtok, &pass, NULL) != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Password not supplied for user %s.\n", pd->user));
        goto done;
    }
    tmp = string2data((char *)pass);
    kerr = krad_attrset_add(rad_req->attrs,
                            krad_attr_name2num("User-Password"),
                            &tmp);
    if (kerr != 0) {
        DEBUG(SSSDBG_OP_FAILURE, ("Could not add User-Password to attribute list.\n"));
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, ("Sending request\n"));
    kerr = krad_client_send(rad_req->client,
                            krad_code_name2num("Access-Request"),
                            rad_req->attrs,
                            dp_opt_get_string(ctx->opts, RAD_SERVER),
                            dp_opt_get_string(ctx->opts, RAD_SECRET),
                            dp_opt_get_int(ctx->opts, RAD_TIMEOUT),
                            dp_opt_get_int(ctx->opts, RAD_CONN_RETRIES),
                            rad_auth_done,
                            rad_req);
    if (kerr != 0) {
        DEBUG(SSSDBG_OP_FAILURE, ("Failed to send client request.\n"));
        retval = ERR_AUTH_FAILED;
        goto done;
    }

    verto_run(rad_req->vctx);
    return retval;

done:
    rad_req_free(rad_req);
    return retval;
}

void rad_auth_handler(struct be_req *be_req)
{
    struct rad_ctx  *rad_ctx;
    struct pam_data *pd;
    int retval;

    pd = talloc_get_type(be_req_get_data(be_req), struct pam_data);
    pd->pam_status = PAM_SYSTEM_ERR;

    rad_ctx = get_rad_ctx(be_req);
    if (rad_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("Radius context not available.\n"));
        goto done;
    }

    retval = rad_auth_send(rad_ctx, pd, be_req);
    if (retval != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Auth request failed to send [%i].\n", retval));
        goto done;
    }

    return;

done:
    be_req_terminate(be_req, DP_ERR_FATAL, pd->pam_status, NULL);
}

static void rad_auth_done(krb5_error_code retval,
                          const krad_packet *req_pkt,
                          const krad_packet *rsp_pkt,
                          void *data)
{
    struct rad_req *req;
    int dp_err = DP_ERR_FATAL;

    req = data;
    req->pd->pam_status = PAM_SYSTEM_ERR;

    //verto_break(req->vctx);

    switch (retval) {
    case 0:
        break;
    case ETIMEDOUT:
        DEBUG(SSSDBG_OP_FAILURE, ("Request timeout. No response from server.\n"));
        break;
    default:
        DEBUG(SSSDBG_OP_FAILURE, ("rad_auth_send failed with code %i.\n", retval));
    }

    if (krad_packet_get_code(rsp_pkt)
        == krad_code_name2num("Access-Accept")) {
        
        DEBUG(SSSDBG_TRACE_FUNC, ("Permission granted for user %s.\n", req->pd->user));
        dp_err = DP_ERR_OK;
        req->pd->pam_status = PAM_SUCCESS;
    } else {
        DEBUG(SSSDBG_TRACE_FUNC, ("Permission denied for user %s.\n", req->pd->user));
        dp_err = DP_ERR_OK;
        req->pd->pam_status = PAM_PERM_DENIED;
    }

    DEBUG(SSSDBG_TRACE_FUNC, ("Callback terminating be_req.\n"));
    be_req_terminate(req->be_req, dp_err, req->pd->pam_status, NULL);
    DEBUG(SSSDBG_TRACE_FUNC, ("Callback freeing req.\n"));
    rad_req_free(req);
    DEBUG(SSSDBG_TRACE_FUNC, ("Callback finished.\n"));
}
