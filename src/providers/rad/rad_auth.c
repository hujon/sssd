#include <security/pam_modules.h>

#include "providers/dp_backend.h"
#include "providers/rad/rad_auth.h"

void rad_auth_handler(struct be_req *be_req)
{
  struct be_ctx *be_ctx = be_req_get_be_ctx(be_req);
  int retval;
  struct pam_data *pd;

  pd = talloc_get_type(be_req_get_data(be_req), struct pam_data);
  pd->pam_status = PAM_SYSTEM_ERR;

  pd->pam_status = PAM_SUCCESS;

  be_req_terminate(be_req, DP_ERR_OK, pd->pam_status, NULL);
}
