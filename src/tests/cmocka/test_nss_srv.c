/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2013 Red Hat

    SSSD tests: Common utilities for tests that exercise domains

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

#include <talloc.h>
#include <tevent.h>
#include <errno.h>
#include <popt.h>

#include "tests/cmocka/common_mock.h"
#include "tests/cmocka/common_mock_resp.h"
#include "responder/common/negcache.h"
#include "responder/nss/nsssrv.h"
#include "responder/nss/nsssrv_private.h"

#define TESTS_PATH "tests_nss"
#define TEST_CONF_DB "test_nss_conf.ldb"
#define TEST_SYSDB_FILE "cache_nss_test.ldb"
#define TEST_DOM_NAME "nss_test"
#define TEST_ID_PROVIDER "ldap"

struct nss_test_ctx {
    struct sss_test_ctx *tctx;

    struct resp_ctx *rctx;
    struct cli_ctx *cctx;
    struct sss_cmd_table *nss_cmds;
    struct nss_ctx *nctx;

    bool ncache_hit;
};

struct nss_test_ctx *nss_test_ctx;

/* Mock NSS structure */
struct nss_ctx *
mock_nctx(TALLOC_CTX *mem_ctx)
{
    struct nss_ctx *nctx;
    errno_t ret;

    nctx = talloc_zero(mem_ctx, struct nss_ctx);
    if (!nctx) {
        return NULL;
    }

    ret = sss_ncache_init(nctx, &nctx->ncache);
    if (ret != EOK) {
        talloc_free(nctx);
        return NULL;
    }
    nctx->neg_timeout = 10;

    return nctx;
}

/* Mock reading requests from a client. Use values passed from mock
 * instead
 */
void __real_sss_packet_get_body(struct sss_packet *packet,
                                uint8_t **body, size_t *blen);

void __wrap_sss_packet_get_body(struct sss_packet *packet,
                                uint8_t **body, size_t *blen)
{
    enum sss_test_wrapper_call wtype = sss_mock_type(enum sss_test_wrapper_call);

    if (wtype == WRAP_CALL_REAL) {
        return __real_sss_packet_get_body(packet, body, blen);
    }

    *body = sss_mock_ptr_type(uint8_t *);
    *blen = strlen((const char *) *body)+1;
    return;
}

/* Mock returning result to client. Terminate the unit test instead. */
typedef int (*cmd_cb_fn_t)(uint8_t *, size_t );

static void set_cmd_cb(cmd_cb_fn_t fn)
{
    will_return(__wrap_sss_cmd_done, fn);
}

void __wrap_sss_cmd_done(struct cli_ctx *cctx, void *freectx)
{
    struct sss_packet *packet = cctx->creq->out;
    uint8_t *body;
    size_t blen;
    cmd_cb_fn_t check_cb;

    check_cb = sss_mock_ptr_type(cmd_cb_fn_t);

    __real_sss_packet_get_body(packet, &body, &blen);

    nss_test_ctx->tctx->error = check_cb(body, blen);
    nss_test_ctx->tctx->done = true;
}

enum sss_cli_command __wrap_sss_packet_get_cmd(struct sss_packet *packet)
{
    return sss_mock_type(enum sss_cli_command);
}

int __wrap_sss_cmd_send_empty(struct cli_ctx *cctx, TALLOC_CTX *freectx)
{
    nss_test_ctx->tctx->done = true;
    nss_test_ctx->tctx->error = ENOENT;
    return EOK;
}

/* Intercept negative cache lookups */
int __real_sss_ncache_check_user(struct sss_nc_ctx *ctx, int ttl,
                                 struct sss_domain_info *dom, const char *name);

int __wrap_sss_ncache_check_user(struct sss_nc_ctx *ctx, int ttl,
                                 struct sss_domain_info *dom, const char *name)
{
    int ret;

    ret = __real_sss_ncache_check_user(ctx, ttl, dom, name);
    if (ret == EEXIST) {
        nss_test_ctx->ncache_hit = true;
    }
    return ret;
}

/* Mock input from the client library */
static void mock_input_user(const char *username)
{
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_WRAPPER);
    will_return(__wrap_sss_packet_get_body, username);
}

static void mock_fill_user(void)
{
    /* One packet for the entry and one for num entries */
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
    will_return(__wrap_sss_packet_get_body, WRAP_CALL_REAL);
}

static int parse_user_packet(uint8_t *body, size_t blen, struct passwd *pwd)
{
    size_t rp = 2 * sizeof(uint32_t);

    SAFEALIGN_COPY_UINT32(&pwd->pw_uid, body+rp, &rp);
    SAFEALIGN_COPY_UINT32(&pwd->pw_gid, body+rp, &rp);

    /* Sequence of null terminated strings (name, passwd, gecos, dir, shell) */
    pwd->pw_name = (char *) body+rp;
    rp += strlen(pwd->pw_name) + 1;
    if (rp >= blen) return EINVAL;

    pwd->pw_gecos = (char *) body+rp;
    rp += strlen(pwd->pw_gecos) + 1;
    if (rp >= blen) return EINVAL;

    pwd->pw_dir = (char *) body+rp;
    rp += strlen(pwd->pw_dir) + 1;
    if (rp >= blen) return EINVAL;

    pwd->pw_shell = (char *) body+rp;
    return EOK;
}

/* ====================== The tests =============================== */

/* Check getting cached and valid user from cache. Account callback will
 * not be called and test_nss_getpwnam_check will make sure the user is
 * the same as the test entered before starting
 */
static int test_nss_getpwnam_check(uint8_t *body, size_t blen)
{
    struct passwd pwd;
    errno_t ret;

    ret = parse_user_packet(body, blen, &pwd);
    assert_int_equal(ret, EOK);

    assert_int_equal(pwd.pw_uid, 123);
    assert_int_equal(pwd.pw_gid, 456);
    assert_string_equal(pwd.pw_name, "testuser");
    assert_string_equal(pwd.pw_shell, "/bin/sh");
    return EOK;
}

void test_nss_getpwnam(void **state)
{
    errno_t ret;

    /* Prime the cache with a valid user */
    ret = sysdb_add_user(nss_test_ctx->tctx->sysdb,
                         nss_test_ctx->tctx->dom,
                         "testuser", 123, 456, "test user",
                         "/home/testuser", "/bin/sh", NULL,
                         NULL, 300, 0);
    assert_int_equal(ret, EOK);

    mock_input_user("testuser");
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETPWNAM);
    mock_fill_user();

    /* Query for that user, call a callback when command finishes */
    set_cmd_cb(test_nss_getpwnam_check);
    ret = sss_cmd_execute(nss_test_ctx->cctx, SSS_NSS_GETPWNAM,
                          nss_test_ctx->nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

/* Test that searching for a nonexistant user yields ENOENT.
 * Account callback will be called
 */
void test_nss_getpwnam_neg(void **state)
{
    errno_t ret;

    mock_input_user("testuser_neg");
    mock_account_recv_simple();

    assert_true(nss_test_ctx->ncache_hit == false);

    ret = sss_cmd_execute(nss_test_ctx->cctx, SSS_NSS_GETPWNAM,
                          nss_test_ctx->nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with ENOENT */
    ret = test_ev_loop(nss_test_ctx->tctx);
    assert_int_equal(ret, ENOENT);
    assert_true(nss_test_ctx->ncache_hit == false);

    /* Test that subsequent search for a nonexistent user yields
     * ENOENT and Account callback is not called, on the other hand
     * the ncache functions will be called
     */
    nss_test_ctx->tctx->done = false;

    mock_input_user("testuser_neg");
    ret = sss_cmd_execute(nss_test_ctx->cctx, SSS_NSS_GETPWNAM,
                          nss_test_ctx->nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with ENOENT */
    ret = test_ev_loop(nss_test_ctx->tctx);
    assert_int_equal(ret, ENOENT);
    /* Negative cache was hit this time */
    assert_true(nss_test_ctx->ncache_hit == true);
}

static int test_nss_getpwnam_search_acct_cb(void *pvt)
{
    errno_t ret;
    struct nss_test_ctx *ctx = talloc_get_type(pvt, struct nss_test_ctx);

    ret = sysdb_add_user(ctx->tctx->sysdb,
                         ctx->tctx->dom,
                         "testuser_search", 567, 890, "test search",
                         "/home/testsearch", "/bin/sh", NULL,
                         NULL, 300, 0);
    assert_int_equal(ret, EOK);

    return EOK;
}

static int test_nss_getpwnam_search_check(uint8_t *body, size_t blen)
{
    struct passwd pwd;
    errno_t ret;

    ret = parse_user_packet(body, blen, &pwd);
    assert_int_equal(ret, EOK);

    assert_int_equal(pwd.pw_uid, 567);
    assert_int_equal(pwd.pw_gid, 890);
    assert_string_equal(pwd.pw_name, "testuser_search");
    assert_string_equal(pwd.pw_shell, "/bin/sh");
    return EOK;
}

void test_nss_getpwnam_search(void **state)
{
    errno_t ret;
    struct ldb_result *res;

    mock_input_user("testuser_search");
    mock_account_recv(0, 0, NULL, test_nss_getpwnam_search_acct_cb, nss_test_ctx);
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETPWNAM);
    mock_fill_user();
    set_cmd_cb(test_nss_getpwnam_search_check);

    ret = sysdb_getpwnam(nss_test_ctx, nss_test_ctx->tctx->sysdb,
                         nss_test_ctx->tctx->dom, "testuser_search",
                         &res);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 0);

    ret = sss_cmd_execute(nss_test_ctx->cctx, SSS_NSS_GETPWNAM,
                          nss_test_ctx->nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);

    /* test_nss_getpwnam_search_check will check the user attributes */
    ret = sysdb_getpwnam(nss_test_ctx, nss_test_ctx->tctx->sysdb,
                         nss_test_ctx->tctx->dom, "testuser_search",
                         &res);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 1);
}

/* Test that searching for a user that is expired in the cache goes to the DP
 * which updates the record and the NSS responder returns the updated record
 *
 * The user's shell attribute is updated.
 */
static int test_nss_getpwnam_update_acct_cb(void *pvt)
{
    errno_t ret;
    struct nss_test_ctx *ctx = talloc_get_type(pvt, struct nss_test_ctx);

    ret = sysdb_store_user(ctx->tctx->sysdb,
                           ctx->tctx->dom,
                           "testuser_update", NULL, 10, 11, "test user",
                           "/home/testuser", "/bin/ksh", NULL,
                           NULL, NULL, 300, 0);
    assert_int_equal(ret, EOK);

    return EOK;
}

static int test_nss_getpwnam_update_check(uint8_t *body, size_t blen)
{
    struct passwd pwd;
    errno_t ret;

    ret = parse_user_packet(body, blen, &pwd);
    assert_int_equal(ret, EOK);

    assert_int_equal(pwd.pw_uid, 10);
    assert_int_equal(pwd.pw_gid, 11);
    assert_string_equal(pwd.pw_name, "testuser_update");
    assert_string_equal(pwd.pw_shell, "/bin/ksh");
    return EOK;
}

void test_nss_getpwnam_update(void **state)
{
    errno_t ret;
    struct ldb_result *res;
    const char *shell;

    /* Prime the cache with a valid but expired user */
    ret = sysdb_add_user(nss_test_ctx->tctx->sysdb,
                         nss_test_ctx->tctx->dom,
                         "testuser_update", 10, 11, "test user",
                         "/home/testuser", "/bin/sh", NULL,
                         NULL, 1, 1);
    assert_int_equal(ret, EOK);

    /* Mock client input */
    mock_input_user("testuser_update");
    /* Mock client command */
    will_return(__wrap_sss_packet_get_cmd, SSS_NSS_GETPWNAM);
    /* Call this function when user is updated by the mock DP request */
    mock_account_recv(0, 0, NULL, test_nss_getpwnam_update_acct_cb, nss_test_ctx);
    /* Call this function to check what the responder returned to the client */
    set_cmd_cb(test_nss_getpwnam_update_check);
    /* Mock output buffer */
    mock_fill_user();

    /* Fire the command */
    ret = sss_cmd_execute(nss_test_ctx->cctx, SSS_NSS_GETPWNAM,
                          nss_test_ctx->nss_cmds);
    assert_int_equal(ret, EOK);

    /* Wait until the test finishes with EOK */
    ret = test_ev_loop(nss_test_ctx->tctx);
    assert_int_equal(ret, EOK);

    /* Check the user was updated in the cache */
    ret = sysdb_getpwnam(nss_test_ctx, nss_test_ctx->tctx->sysdb,
                         nss_test_ctx->tctx->dom, "testuser_update",
                         &res);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 1);

    shell = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_SHELL, NULL);
    assert_string_equal(shell, "/bin/ksh");
}

/* Testsuite setup and teardown */
void nss_test_setup(void **state)
{
    errno_t ret;
    struct sss_test_conf_param params[] = {
        { "enumerate", "false" },
        { NULL, NULL },             /* Sentinel */
    };

    nss_test_ctx = talloc_zero(NULL, struct nss_test_ctx);
    assert_non_null(nss_test_ctx);

    nss_test_ctx->tctx = create_dom_test_ctx(nss_test_ctx, TESTS_PATH, TEST_CONF_DB,
                                             TEST_SYSDB_FILE, TEST_DOM_NAME,
                                             TEST_ID_PROVIDER, params);
    assert_non_null(nss_test_ctx->tctx);

    nss_test_ctx->nss_cmds = get_nss_cmds();
    assert_non_null(nss_test_ctx->nss_cmds);

    /* FIXME - perhaps this should be folded into sssd_domain_init or stricty
     * used together
     */
    ret = sss_names_init(nss_test_ctx, nss_test_ctx->tctx->confdb,
                         TEST_DOM_NAME, &nss_test_ctx->tctx->dom->names);
    assert_int_equal(ret, EOK);

    /* Initialize the NSS responder */
    nss_test_ctx->nctx = mock_nctx(nss_test_ctx);
    assert_non_null(nss_test_ctx->nctx);

    nss_test_ctx->rctx = mock_rctx(nss_test_ctx, nss_test_ctx->tctx->ev,
                                   nss_test_ctx->tctx->dom, nss_test_ctx->nctx);
    assert_non_null(nss_test_ctx->rctx);

    /* Create client context */
    nss_test_ctx->cctx = mock_cctx(nss_test_ctx, nss_test_ctx->rctx);
    assert_non_null(nss_test_ctx->cctx);
}

void nss_test_teardown(void **state)
{
    talloc_free(nss_test_ctx);
}

int main(int argc, const char *argv[])
{
    int rv;
    int no_cleanup = 0;
    poptContext pc;
    int opt;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_DEBUG_OPTS
        {"no-cleanup", 'n', POPT_ARG_NONE, &no_cleanup, 0,
         _("Do not delete the test database after a test run"), NULL },
        POPT_TABLEEND
    };

    const UnitTest tests[] = {
        unit_test_setup_teardown(test_nss_getpwnam,
                                 nss_test_setup, nss_test_teardown),
        unit_test_setup_teardown(test_nss_getpwnam_neg,
                                 nss_test_setup, nss_test_teardown),
        unit_test_setup_teardown(test_nss_getpwnam_search,
                                 nss_test_setup, nss_test_teardown),
        unit_test_setup_teardown(test_nss_getpwnam_update,
                                 nss_test_setup, nss_test_teardown),
    };

    /* Set debug level to invalid value so we can deside if -d 0 was used. */
    debug_level = SSSDBG_INVALID;

    pc = poptGetContext(argv[0], argc, argv, long_options, 0);
    while((opt = poptGetNextOpt(pc)) != -1) {
        switch(opt) {
        default:
            fprintf(stderr, "\nInvalid option %s: %s\n\n",
                    poptBadOption(pc, 0), poptStrerror(opt));
            poptPrintUsage(pc, stderr, 0);
            return 1;
        }
    }
    poptFreeContext(pc);

    DEBUG_INIT(debug_level);

    /* Even though normally the tests should clean up after themselves
     * they might not after a failed run. Remove the old db to be sure */
    tests_set_cwd();
    test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, TEST_SYSDB_FILE);
    test_dom_suite_setup(TESTS_PATH);

    rv = run_tests(tests);
    if (rv == 0 && !no_cleanup) {
        test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, TEST_SYSDB_FILE);
    }
    return rv;
}
