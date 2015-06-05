/*
 * Copyright (C) 2010 SCALITY SA. All rights reserved.
 * http://www.scality.com
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY SCALITY SA ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL SCALITY SA OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * The views and conclusions contained in the software and documentation
 * are those of the authors and should not be interpreted as representing
 * official policies, either expressed or implied, of SCALITY SA.
 *
 * https://github.com/scality/Droplet
 */
#include "dropletp.h"

/** @file */

//#define DPRINTF(fmt,...) fprintf(stderr, fmt, ##__VA_ARGS__)
#define DPRINTF(fmt,...)

dpl_status_t
dpl_add_host_to_headers(dpl_req_t *req,
                        dpl_dict_t *headers)
{
  dpl_status_t ret;

  if (NULL != req->host)
    {
      char buf[256];

      if (strcmp("80", req->port))
        snprintf(buf, sizeof (buf), "%s:%s", req->host, req->port);
      else
        snprintf(buf, sizeof (buf), "%s", req->host);

      ret = dpl_dict_add(headers, "Host", buf, 0);
      if (DPL_SUCCESS != ret)
        {
          return ret;
        }
    }

  return DPL_SUCCESS;
}

dpl_status_t
dpl_add_range_to_headers_internal(const dpl_range_t *range,
                                  const char *field,
                                  dpl_dict_t *headers)
{
  int ret;
  char buf[1024];
  size_t len = sizeof (buf);
  char *p;
  int first = 1;
  char str[128];

  p = buf;

  if (dpl_append_str("bytes=", &p, &len) != DPL_SUCCESS)
    return DPL_FAILURE;

  if (1 == first)
    first = 0;
  else
    if (dpl_append_str(",", &p, &len) != DPL_SUCCESS)
      return DPL_FAILURE;
  
  if (DPL_UNDEF == range->start && DPL_UNDEF == range->end)
    return DPL_EINVAL;
  else if (DPL_UNDEF == range->start)
    {
      snprintf(str, sizeof (str), "-%lu", range->end);
      if (dpl_append_str(str, &p, &len) != DPL_SUCCESS)
        return DPL_FAILURE;
    }
  else if (DPL_UNDEF == range->end)
    {
      snprintf(str, sizeof (str), "%lu-", range->start);
      if (dpl_append_str(str, &p, &len) != DPL_SUCCESS)
        return DPL_FAILURE;
    }
  else
    {
      snprintf(str, sizeof (str), "%lu-%lu", range->start, range->end);
      if (dpl_append_str(str, &p, &len) != DPL_SUCCESS)
        return DPL_FAILURE;
    }

  DPL_APPEND_CHAR(0);
  
  ret = dpl_dict_add(headers, field, buf, 0);
  if (DPL_SUCCESS != ret)
    {
      return DPL_FAILURE;
    }

  return DPL_SUCCESS;
}

dpl_status_t
dpl_add_range_to_headers(const dpl_range_t *range,
                         dpl_dict_t *headers)
{
  return dpl_add_range_to_headers_internal(range, "Range", headers);
}

dpl_status_t
dpl_add_content_range_to_headers(const dpl_range_t *range,
                                 dpl_dict_t *headers)
{
  return dpl_add_range_to_headers_internal(range, "Content-Range", headers);
}

dpl_status_t
dpl_add_condition_to_headers(const dpl_condition_t *cond,
                             dpl_dict_t *headers)
{
  int ret;
  char *header;
  int i;

  for (i = 0;i < cond->n_conds;i++)
    {
      const dpl_condition_one_t *condition = &cond->conds[i];

      if (condition->type == DPL_CONDITION_IF_MODIFIED_SINCE ||
          condition->type == DPL_CONDITION_IF_UNMODIFIED_SINCE)
        {
          char date_str[128];
          struct tm tm_buf;
          
          ret = strftime(date_str, sizeof (date_str), "%a, %d %b %Y %H:%M:%S GMT", gmtime_r(&condition->time, &tm_buf));
          if (0 == ret)
            return DPL_FAILURE;
          
          if (condition->type == DPL_CONDITION_IF_MODIFIED_SINCE)
            {
              header = "If-Modified-Since";
              ret = dpl_dict_add(headers, header, date_str, 0);
              if (DPL_SUCCESS != ret)
                {
                  return DPL_FAILURE;
                }
            }
          
          if (condition->type == DPL_CONDITION_IF_UNMODIFIED_SINCE)
            {
              header = "If-Unmodified-Since";
              ret = dpl_dict_add(headers, header, date_str, 0);
              if (DPL_SUCCESS != ret)
                {
                  return DPL_FAILURE;
                }
            }
        }
      
      if (condition->type == DPL_CONDITION_IF_MATCH)
        {
          header = "If-Match";
          ret = dpl_dict_add(headers, header, condition->etag, 0);
          if (DPL_SUCCESS != ret)
            {
              return DPL_FAILURE;
            }
        }
      
      if (condition->type == DPL_CONDITION_IF_NONE_MATCH)
        {
          header = "If-None-Match";
          ret = dpl_dict_add(headers, header, condition->etag, 0);
          if (DPL_SUCCESS != ret)
            {
              return DPL_FAILURE;
            }
        }
    }

  return DPL_SUCCESS;
}

/* Add RFC2617 Basic authorization to a request's headers */
dpl_status_t
dpl_add_basic_authorization_to_headers(const dpl_req_t *req,
				       dpl_dict_t *headers)
{
  int ret, ret2;
  char basic_str[1024];
  int basic_len;
  char base64_str[1024];
  int base64_len;
  char auth_str[1024];

  /* No username or no password in the profile means
   * we silently don't send the header */
  if (NULL == req->ctx->access_key ||
      NULL == req->ctx->secret_key)
    return DPL_SUCCESS;

  snprintf(basic_str, sizeof (basic_str), "%s:%s", req->ctx->access_key, req->ctx->secret_key);
  basic_len = strlen(basic_str);

  base64_len = dpl_base64_encode((const u_char *) basic_str, basic_len, (u_char *) base64_str);

  snprintf(auth_str, sizeof (auth_str), "Basic %.*s", base64_len, base64_str);

  ret2 = dpl_dict_add(headers, "Authorization", auth_str, 0);
  if (DPL_SUCCESS != ret2)
    {
      ret = ret2;
      goto end;
    }

  ret = DPL_SUCCESS;

 end:

  return ret;
}


/**
 * generate HTTP request
 *
 * @param req
 * @param headers
 * @param query_params
 * @param buf
 * @param len
 * @param lenp
 *
 * @return
 */
dpl_status_t
dpl_req_gen_http_request(dpl_ctx_t *ctx,
                         dpl_req_t *req,
                         const dpl_dict_t *headers,
                         const dpl_dict_t *query_params,
                         char *buf,
                         size_t len,
                         unsigned int *lenp)
{
  int ret;
  char *p;
  char *method = dpl_method_str(req->method);
  char *resource_ue = NULL;

  DPL_TRACE(req->ctx, DPL_TRACE_REQ, "req_gen_http_request resource=%s", req->resource);

  p = buf;

  //resource
  if (NULL != req->resource) {
    resource_ue = malloc(DPL_URL_LENGTH(strlen(req->resource)) + 3);
    if (resource_ue == NULL) {
      ret = DPL_ENOMEM;
      goto end;
    }

    if (ctx->url_encoding) {
      if (ctx->encode_slashes) {
        resource_ue[0] = '/';
        if (*req->resource != '/')
          dpl_url_encode(req->resource, resource_ue + 1);
        else
          dpl_url_encode(req->resource + 1, resource_ue + 1);
      } else {
        if (*req->resource != '/') {
          resource_ue[0] = '/';
          dpl_url_encode_no_slashes(req->resource, resource_ue + 1);
        } else
          dpl_url_encode_no_slashes(req->resource, resource_ue);
      }
    } else {
      if (*req->resource != '/') {
        resource_ue[0] = '/';
        strcpy(resource_ue + 1, req->resource);
      } else
        strcpy(resource_ue, req->resource);
    }
  }
      
  //method
  if (dpl_append_str(method, &p, &len) != DPL_SUCCESS || dpl_append_str(" ", &p, &len) != DPL_SUCCESS)
    {
       ret = DPL_FAILURE;
       goto end;
    }

  if (resource_ue != NULL)
    if (dpl_append_str(resource_ue, &p, &len) != DPL_SUCCESS)
      {
         ret = DPL_FAILURE;
         goto end;
      }

  //subresource and query params
  if (NULL != req->subresource || NULL != query_params)
    if (dpl_append_str("?", &p, &len) != DPL_SUCCESS)
      {
         ret = DPL_FAILURE;
         goto end;
      }

  if (NULL != req->subresource)
    if (dpl_append_str(req->subresource, &p, &len) != DPL_SUCCESS)
      {
         ret = DPL_FAILURE;
         goto end;
      }

  if (NULL != query_params)
    {
      int bucket;
      dpl_dict_var_t *var;
      int amp = 0;

      if (NULL != req->subresource)
        amp = 1;

      for (bucket = 0;bucket < query_params->n_buckets;bucket++)
        {
          for (var = query_params->buckets[bucket];var;var = var->prev)
            {
              if (amp)
                if (dpl_append_str("&", &p, &len) != DPL_SUCCESS)
                  {
                     ret = DPL_FAILURE;
                     goto end;
                  }
              if (dpl_append_str(var->key, &p, &len) != DPL_SUCCESS ||
                dpl_append_str("=", &p, &len) != DPL_SUCCESS)
                {
                   ret = DPL_FAILURE;
                   goto end;
                }
              assert(var->val->type == DPL_VALUE_STRING);
              if (dpl_append_str(dpl_sbuf_get_str(var->val->string), &p, &len) != DPL_SUCCESS)
                {
                   ret = DPL_FAILURE;
                   goto end;
                }
              amp = 1;
            }
        }
    }

  //version
  if (dpl_append_str(" ", &p, &len) != DPL_SUCCESS ||
    dpl_append_str("HTTP/1.1", &p, &len) != DPL_SUCCESS ||
    dpl_append_str("\r\n", &p, &len) != DPL_SUCCESS)
    {
      ret = DPL_FAILURE;
      goto end;
    }

  //headers
  if (NULL != headers)
    {
      int bucket;
      dpl_dict_var_t *var;

      for (bucket = 0;bucket < headers->n_buckets;bucket++)
        {
          for (var = headers->buckets[bucket];var;var = var->prev)
            {
              assert(var->val->type == DPL_VALUE_STRING);
              DPL_TRACE(req->ctx, DPL_TRACE_REQ, "header='%s' value='%s'",
			var->key, dpl_sbuf_get_str(var->val->string));

              if (dpl_append_str(var->key, &p, &len) != DPL_SUCCESS ||
                dpl_append_str(": ", &p, &len) != DPL_SUCCESS ||
                dpl_append_str(dpl_sbuf_get_str(var->val->string), &p, &len) != DPL_SUCCESS ||
                dpl_append_str("\r\n", &p, &len) != DPL_SUCCESS)
                {
                  ret = DPL_FAILURE;
                  goto end;
                }
            }
        }
    }

  //final crlf managed by caller

  if (NULL != lenp)
    *lenp = (p - buf);

  ret = DPL_SUCCESS;
  
 end:
  
  if (NULL != resource_ue)
    free(resource_ue);
  return ret;
}
