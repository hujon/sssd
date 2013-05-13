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
#include <stdio.h>

#include "providers/dp_backend.h"
#include "providers/rad/rad_auth.h"
#include "providers/rad/rad_common.h"

#define PROTOCOL_LEN 25

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

struct rad_state {
    struct tevent_context *ev;
    struct tevent_req *req;
    struct rad_req *rad_req;

    krb5_context kctx;
    krad_attrset *attrs;
    krad_client *client;
    verto_ctx *vctx;

    int pam_status;
    int dp_err;
};

/* RADIUS request oriented objects */

struct rad_req {
    struct rad_ctx *rad_ctx;
    struct pam_data *pd;
    struct be_req *be_req;
};

static int rad_state_destructor(void *mem)
{
    struct rad_state *self = talloc_get_type(mem, struct rad_state);

    DEBUG(SSSDBG_TRACE_FUNC, ("Destructor freeing req.\n"));
    
    if (self->attrs != NULL)
        krad_attrset_free(self->attrs);
    if (self->client != NULL)
        krad_client_free(self->client);
    if (self->kctx != NULL)
        krb5_free_context(self->kctx);
 /*   if (self->vctx != NULL)
        verto_free(self->vctx);
*/
    return 0;
}

/* krad oriented objects */

static inline krb5_data string2data(const char *str)
{
    krb5_data d;

    d.magic = KV5M_DATA;
    d.data = strdup(str);
    d.length = strlen(str);

    return d;
}

static krb5_error_code add_str_attr(krad_attrset *attrs,
                                    const char *attr_name,
                                    const char *attr_val)
{
    krb5_data tmp;
    krb5_error_code retval;

    tmp = string2data(attr_val);
    retval = krad_attrset_add(attrs,
                              krad_attr_name2num(attr_name),
                              &tmp);
    free(tmp.data);
    return retval;
}

static void rad_server_done(krb5_error_code retval,
                            const krad_packet *req,
                            const krad_packet *response,
                            void *data);

static int rad_server_send(struct rad_state *state)
{
    struct rad_req *rad_req = state->rad_req;
    const char *pass = NULL;
    char server_name[HOST_NAME_MAX+1+PROTOCOL_LEN+1];
    krb5_error_code kerr;

    snprintf(server_name, sizeof(server_name), "%s:%s",
             dp_opt_get_string(rad_req->rad_ctx->opts, RAD_SERVER),
             dp_opt_get_string(rad_req->rad_ctx->opts, RAD_PORT));


    kerr = krb5_init_context(&state->kctx);
    if (kerr != 0) {
        DEBUG(SSSDBG_OP_FAILURE, ("Could not initialize KRB5 context.\n"));
        state->kctx = NULL;
        return ERR_AUTH_FAILED;
    }
   
    state->vctx = verto_default(NULL, VERTO_EV_TYPE_IO | VERTO_EV_TYPE_TIMEOUT);
    if (state->vctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("Verto context initialization failed.\n"));
        return ERR_AUTH_FAILED;
    }
    
    kerr = krad_client_new(state->kctx, state->vctx, &state->client);
    if (kerr != 0) {
        DEBUG(SSSDBG_OP_FAILURE, ("Could not initialize radius client.\n"));
        state->client = NULL;
        return ERR_AUTH_FAILED;
    }
   
    kerr = krad_attrset_new(state->kctx, &state->attrs);
    if (kerr != 0) {
        DEBUG(SSSDBG_OP_FAILURE, ("Could not initialize attribute list.\n"));
        state->attrs = NULL;
        return ERR_AUTH_FAILED;
    }
    kerr = add_str_attr(state->attrs, "User-Name", rad_req->pd->user);
    if (kerr != 0) {
        DEBUG(SSSDBG_OP_FAILURE, ("Could not add User-Name to attribute list.\n"));
        return ERR_AUTH_FAILED;
    }
    if (sss_authtok_get_password(rad_req->pd->authtok, &pass, NULL) != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Password not supplied for user %s.\n", rad_req->pd->user));
        return ERR_AUTH_FAILED;
    }
    kerr = add_str_attr(state->attrs, "User-Password", pass);
    pass = NULL;
    if (kerr != 0) {
        DEBUG(SSSDBG_OP_FAILURE, ("Could not add User-Password to attribute list.\n"));
        return ERR_AUTH_FAILED;
    }
    kerr = krad_attrset_add_number(state->attrs,
                                   krad_attr_name2num("Service-Type"),
                                   KRAD_SERVICE_TYPE_LOGIN);
    if (kerr != 0) {
        DEBUG(SSSDBG_OP_FAILURE, ("Could not add Service-Type to attribute list.\n"));
        return ERR_AUTH_FAILED;
    }
    if (dp_opt_get_string(rad_req->rad_ctx->opts, RAD_IDENTIFIER) != NULL) {
        kerr = add_str_attr(state->attrs,
                            "NAS-Identifier",
                            dp_opt_get_string(rad_req->rad_ctx->opts, RAD_IDENTIFIER));
        if (kerr != 0) {
            DEBUG(SSSDBG_MINOR_FAILURE, ("Could not add NAS-Identifier to attribute list.\n"));
        }
    }

    DEBUG(SSSDBG_TRACE_FUNC, ("Sending request.\n"));
    kerr = krad_client_send(state->client,
                            krad_code_name2num("Access-Request"),
                            state->attrs,
                            server_name,
                            dp_opt_get_string(rad_req->rad_ctx->opts, RAD_SECRET),
                            dp_opt_get_int(rad_req->rad_ctx->opts, RAD_TIMEOUT),
                            dp_opt_get_int(rad_req->rad_ctx->opts, RAD_CONN_RETRIES),
                            rad_server_done,
                            state);
    if (kerr != 0) {
        DEBUG(SSSDBG_OP_FAILURE, ("Failed to send client request.\n"));
        return ERR_AUTH_FAILED;
    }
    
    verto_run(state->vctx);

    return EOK;
}

static void rad_server_done(krb5_error_code retval,
                            const krad_packet *req_pkt,
                            const krad_packet *rsp_pkt,
                            void *data)
{
    struct rad_state *state = data;
    int code;

    DEBUG(SSSDBG_TRACE_FUNC, ("Breaking verto.\n"));
    verto_break(state->vctx);

    switch (retval) {
    case EOK:
        break;
    case ETIMEDOUT:
        DEBUG(SSSDBG_OP_FAILURE, ("Request timeout. No response from server.\n"));
        state->dp_err = DP_ERR_TIMEOUT;
        break;
    default:
        DEBUG(SSSDBG_OP_FAILURE, ("rad_server_send failed with code %i.\n", retval));
    }

    code = krad_packet_get_code(rsp_pkt);
    if (code == krad_code_name2num("Access-Accept")) {
        DEBUG(SSSDBG_TRACE_FUNC, 
              ("Permission granted for user %s.\n", state->rad_req->pd->user));
        state->dp_err = DP_ERR_OK;
        state->pam_status = PAM_SUCCESS;
    } else if (code == krad_code_name2num("Access-Reject")) {
        DEBUG(SSSDBG_TRACE_FUNC, 
              ("Permission denied for user %s.\n", state->rad_req->pd->user));
        state->dp_err = DP_ERR_OK;
        state->pam_status = PAM_PERM_DENIED;
    } else if (code == krad_code_name2num("Access-Challenge")) {
        /* TODO: maybe add some handling for challenges in the future? */
    }

    tevent_req_done(state->req);
}

/* tevent subrequest oriented objects */

static void rad_auth_wakeup(struct tevent_req *req);
static void rad_auth_done(struct tevent_req *req);

static struct tevent_req *rad_auth_send(TALLOC_CTX *mem_ctx,
                                        struct tevent_context *ev,
                                        struct rad_req *rad_req)
{
    struct tevent_req *req, *subreq;
    struct rad_state *state;
    struct timeval tv;

    req = tevent_req_create(rad_req, &state, struct rad_state);
    if (req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("tevent_req_create failed.\n"));
        return NULL;
    }
    talloc_set_destructor((TALLOC_CTX *)state, rad_state_destructor);
    state->ev = ev;
    state->req = req;
    state->rad_req = rad_req;
    state->pam_status = PAM_SYSTEM_ERR;
    state->dp_err = DP_ERR_FATAL;
 
    /*
     * We need to have a wrapper around rad_server_send because
     * of the use of verto library for inner loop to make sure
     * that callback is set before rad_server_send is called.
     */
    tv = tevent_timeval_current();
    subreq = tevent_wakeup_send(req, ev, tv);
    if (subreq == NULL) {
        DEBUG(1, ("Failed to add critical timer to run next operation!\n"));
        talloc_zfree(req);
        return NULL;
    }
    tevent_req_set_callback(subreq, rad_auth_wakeup, state);
    
    return req;
}

static void rad_auth_wakeup(struct tevent_req *req)
{
    struct rad_state *state = tevent_req_callback_data(req, struct rad_state);
    int retval;
    
    DEBUG(SSSDBG_TRACE_FUNC, ("Calling rad_server_send.\n"));
    retval = rad_server_send(state);
    if (retval != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("rad_server_send failed.\n"));
        tevent_req_error(state->req, retval);
        tevent_req_post(state->req, state->ev);
    }
}

static int rad_auth_recv(struct tevent_req *req, int *pam_status, int *dp_err)
{
    struct rad_state *state = tevent_req_data(req, struct rad_state);
    *pam_status = state->pam_status;
    *dp_err = state->dp_err;

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

/* interface objects */

void rad_auth_handler(struct be_req *be_req)
{    
    struct be_ctx *be_ctx = be_req_get_be_ctx(be_req);
    struct rad_ctx  *rad_ctx;
    struct pam_data *pd;
    struct rad_req *rad_req;
    struct tevent_req *subreq;

    pd = talloc_get_type(be_req_get_data(be_req), struct pam_data);
    pd->pam_status = PAM_SYSTEM_ERR;

    rad_ctx = get_rad_ctx(be_req);
    if (rad_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("Radius context not available.\n"));
        goto done;
    }
    
    rad_req = talloc_zero(be_req, struct rad_req);
    if (rad_req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("talloc_zero failed.\n"));
        goto done;
    }
    rad_req->rad_ctx = rad_ctx;
    rad_req->pd = pd;
    rad_req->be_req = be_req;

    subreq = rad_auth_send(rad_req, be_ctx->ev, rad_req);
    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("Auth request failed to create subrequest.\n"));
        goto done;
    }
    tevent_req_set_callback(subreq, rad_auth_done, rad_req);
    DEBUG(SSSDBG_TRACE_FUNC, ("Callback set.\n"));

    return;

done:
    be_req_terminate(be_req, DP_ERR_FATAL, pd->pam_status, NULL);
}

static void rad_auth_done(struct tevent_req *req)
{
    struct rad_req *rad_req = tevent_req_callback_data(req, struct rad_req);
    int pam_status;
    int dp_err;
    int retval;

    retval = rad_auth_recv(req, &pam_status, &dp_err);
    talloc_zfree(req);
    if (retval != EOK) {
        pam_status = PAM_SYSTEM_ERR;
        dp_err = DP_ERR_OK;
    }
    rad_req->pd->pam_status = pam_status;

    be_req_terminate(rad_req->be_req, dp_err, pam_status, NULL);
    DEBUG(SSSDBG_TRACE_FUNC, ("Request finished.\n"));
}
