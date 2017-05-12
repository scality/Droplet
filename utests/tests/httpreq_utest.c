#include <check.h>

#include "dropletp.h"
#include "droplet/s3/s3.h"

#include "utest_main.h"

/* Fri, 24 May 2013 00:00:00 GMT */
static struct tm test_date = {
  .tm_sec = 0,
  .tm_min = 0,
  .tm_hour = 0,
  .tm_mday = 24,
  .tm_mon = 4,
  .tm_year = 113,
  .tm_wday = 5
};

static dpl_ctx_t *
httpreq_create_ctx_for_test(unsigned char version,
                            int virtual_hosting)
{
  dpl_ctx_t     *ctx;
  dpl_dict_t    *profile;
  dpl_status_t  ret;

  profile = dpl_dict_new(32);
  dpl_assert_ptr_not_null(profile);

  ret = dpl_dict_add(profile, "backend", "s3", 0);
  dpl_assert_int_eq(DPL_SUCCESS, ret);

  ret = dpl_dict_add(profile, "use_https", "false", 0);
  dpl_assert_int_eq(DPL_SUCCESS, ret);

  ret = dpl_dict_add(profile, "host", "s3.amazonaws.com", 0);
  dpl_assert_int_eq(DPL_SUCCESS, ret);

  ret = dpl_dict_add(profile, "virtual_hosting",
                     virtual_hosting ? "true" : "false", 0);
  dpl_assert_int_eq(DPL_SUCCESS, ret);

  ctx = dpl_ctx_new_from_dict(profile);
  dpl_assert_ptr_not_null(ctx);

  dpl_dict_free(profile);

  return ctx;
}

static dpl_req_t *
httpreq_create_req_for_test(dpl_ctx_t *ctx, dpl_method_t method,
                            const char *bucket, const char *resource,
                            dpl_dict_t **headers)
{
  dpl_addr_t    *addrp = NULL;
  dpl_status_t  ret;
  dpl_req_t     *req;
  char          virtual_host[1024];

  req = dpl_req_new(ctx);
  dpl_assert_ptr_not_null(req);

  dpl_req_set_method(req, method);

  if (bucket != NULL) {
    ret = dpl_req_set_bucket(req, bucket);
    dpl_assert_int_eq(DPL_SUCCESS, ret);
  }

  ret = dpl_req_set_resource(req, resource);
  dpl_assert_int_eq(DPL_SUCCESS, ret);

  ret = dpl_s3_req_build(req, 0u, headers);
  dpl_assert_int_eq(DPL_SUCCESS, ret);

  ret = dpl_addrlist_get_nth(ctx->addrlist, ctx->cur_host, &addrp);
  dpl_assert_int_eq(DPL_SUCCESS, ret);
  dpl_assert_ptr_not_null(addrp);

  ret = dpl_req_set_port(req, addrp->portstr);
  dpl_assert_int_eq(DPL_SUCCESS, ret);

  ret = dpl_add_host_to_headers(req, *headers);
  dpl_assert_int_eq(DPL_SUCCESS, ret);

  return req;
}

START_TEST(httpreq_test1)
{
  dpl_ctx_t             *ctx;
  dpl_req_t             *req;
  dpl_dict_t            *headers = NULL;
  dpl_status_t          ret;
  dpl_dict_var_t        *var;
  char                  *authorization;
  char                  *header;
  u_int                 header_len;
  char                  *p;

  ctx = httpreq_create_ctx_for_test(4, 1);
  req = httpreq_create_req_for_test(ctx, DPL_METHOD_GET, "examplebucket", "/test.txt", &headers);

  header = alloca(dpl_header_size); //dpl_header_size is inited at ctx creation

  memset(header, 0, dpl_header_size); //XXX why ?
  ret = dpl_req_gen_http_request(ctx, req, headers, NULL, header, dpl_header_size, &header_len);
  dpl_assert_int_eq(DPL_SUCCESS, ret);

  p = index(header, '\r');
  dpl_assert_ptr_not_null(p);
  *p++ = 0;
  dpl_assert_str_eq(header, "GET /test.txt HTTP/1.1");

  if (headers != NULL)
    dpl_dict_free(headers);

  dpl_req_free(req);
  dpl_ctx_free(ctx);
}
END_TEST

START_TEST(httpreq_test2)
{
  dpl_ctx_t             *ctx;
  dpl_req_t             *req;
  dpl_dict_t            *headers = NULL;
  dpl_status_t          ret;
  dpl_dict_var_t        *var;
  char                  *authorization;
  char                  *header;
  u_int                 header_len;
  char                  *p;

  ctx = httpreq_create_ctx_for_test(4, 0);
  req = httpreq_create_req_for_test(ctx, DPL_METHOD_GET, "examplebucket", "/test.txt", &headers);

  header = alloca(dpl_header_size); //dpl_header_size is inited at ctx creation

  memset(header, 0, dpl_header_size); //XXX why ?
  ret = dpl_req_gen_http_request(ctx, req, headers, NULL, header, dpl_header_size, &header_len);
  dpl_assert_int_eq(DPL_SUCCESS, ret);

  p = index(header, '\r');
  dpl_assert_ptr_not_null(p);
  *p++ = 0;
  dpl_assert_str_eq(header, "GET /examplebucket/test.txt HTTP/1.1");

  if (headers != NULL)
    dpl_dict_free(headers);

  dpl_req_free(req);
  dpl_ctx_free(ctx);
}
END_TEST

Suite *
httpreq_suite(void)
{
  Suite *s = suite_create("httpreq");
  TCase *d = tcase_create("base");
  tcase_add_test(d, httpreq_test1);
  tcase_add_test(d, httpreq_test2);
  suite_add_tcase(s, d);
  return s;
}
