#include <security/pam_modules.h>

#include "providers/dp_backend.h"
#include "providers/rad/rad_auth.h"
#include "providers/rad/rad_common.h"

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
    case SSS_PAM_ACCT_MGMT:
        return talloc_get_type(be_ctx->bet_info[BET_ACCESS].pvt_bet_data,
                              struct rad_ctx);
        break;
    case SSS_PAM_CHAUTHTOK:
    case SSS_PAM_CHAUTHTOK_PRELIM:
        return talloc_get_type(be_ctx->bet_info[BET_CHPASS].pvt_bet_data,
                              struct rad_ctx);
        break;
    default:
        DEBUG(SSSDBG_OP_FAILURE, ("Unsupported PAM task.\n"));
        return NULL;
    }
}

void rad_auth_handler(struct be_req *be_req)
{
    int retval;
    struct be_ctx *be_ctx = be_req_get_be_ctx(be_req);
    struct rad_ctx  *rad_ctx;
    struct pam_data *pd;
    int dp_err = DP_ERR_FATAL;

    pd = talloc_get_type(be_req_get_data(be_req), struct pam_data);
    pd->pam_status = PAM_SYSTEM_ERR;

    rad_ctx = get_rad_ctx(be_req);
    if (rad_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("Radius context not available\n"));
        be_req_terminate(be_req, dp_err, pd->pam_status, NULL);
        return;
    }

    dp_err = DP_ERR_OK;
    if (dp_opt_get_bool(rad_ctx->opts, RAD_TMP)) {
        pd->pam_status = PAM_SUCCESS;
    } else {
        pd->pam_status = PAM_PERM_DENIED;
    }

    be_req_terminate(be_req, dp_err, pd->pam_status, NULL);
}
