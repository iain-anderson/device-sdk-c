/*
 * Copyright (c) 2021
 * IoTech Ltd
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#include "secrets-vault.h"
#include "rest.h"
#include "edgex-rest.h"
#include "parson.h"
#include "errorlist.h"

typedef struct vault_impl_t
{
  iot_logger_t *lc;
  char *token;
  char *baseurl;
} vault_impl_t;

static void vault_init (void *impl, iot_logger_t *lc, iot_data_t *config)
{
  vault_impl_t *vault = (vault_impl_t *)impl;
  vault->lc = lc;

  const char *path = iot_data_string_map_get_string (config, "SecretStore/Path");
  vault->baseurl = malloc (URL_BUF_SIZE);
  snprintf
  (
    vault->baseurl, URL_BUF_SIZE,
    "%s://%s:%u%s%s%s",
    iot_data_string_map_get_string (config, "SecretStore/Protocol"),
    iot_data_string_map_get_string (config, "SecretStore/Host"),
    iot_data_ui16 (iot_data_string_map_get (config, "SecretStore/Port")),
    path[0] == '/' ? "" : "/",
    path,
    path[strlen (path) - 1] == '/' ? "" : "/"
  );

  const char *fname = iot_data_string_map_get_string (config, "SecretStore/TokenFile");
  JSON_Value *jval = json_parse_file (fname);
  if (jval)
  {
    JSON_Object *jobj = json_value_get_object (jval);
    JSON_Object *aobj = json_object_get_object (jobj, "auth");
    if (aobj)
    {
      const char *ctok = json_object_get_string (aobj, "client_token");
      if (ctok)
      {
        vault->token = strdup (ctok);
      }
    }
    if (vault->token == NULL)
    {
      iot_log_error (vault->lc, "vault: Unable to find client token in file %s", fname);
    }
    json_value_free (jval);
    // TODO: root token (for refreshing client tok)
  }
  else
  {
    iot_log_error (vault->lc, "vault: Token file %s doesn't parse as JSON", fname);
  }
  // TODO: SecretStore/Authentication/AuthType can be "X-Vault-Token" or "Authorization" (Bearer)
  // TODO: SecretStore/RetryWaitPeriod
  // TODO: SecretStore/AdditionalRetryAttempts
  // TODO: SecretStore/ServerName
  // TODO: SecretStore/RootCaCertPath
}

static void vault_reconfigure (void *impl, iot_data_t *config)
{
}

static devsdk_nvpairs *vault_get (void *impl, const char *path)
{
  devsdk_nvpairs *result = NULL;
  edgex_ctx ctx;
  devsdk_error err = EDGEX_OK;
  char url[URL_BUF_SIZE];
  vault_impl_t *vault = (vault_impl_t *)impl;

  memset (&ctx, 0, sizeof (edgex_ctx));
  snprintf (url, URL_BUF_SIZE - 1, "%s%s", vault->baseurl, path);
  ctx.jwt_token = vault->token;
  edgex_http_get (vault->lc, &ctx, url, edgex_http_write_cb, &err);
  if (err.code == 0)
  {
    JSON_Value *jval = json_parse_string (ctx.buff);
    JSON_Object *jobj = json_value_get_object (jval);
    JSON_Object *data = json_object_get_object (jobj, "data");
    result = devsdk_nvpairs_read (data);
    json_value_free (jval);
  }
  else
  {
    iot_log_error (vault->lc, "vault: get secrets request failed");
  }
  free (ctx.buff);

  return result;
}

static void vault_set (void *impl, const char *path, const devsdk_nvpairs *secrets)
{
  edgex_ctx ctx;
  devsdk_error err = EDGEX_OK;
  char url[URL_BUF_SIZE];
  vault_impl_t *vault = (vault_impl_t *)impl;

  memset (&ctx, 0, sizeof (edgex_ctx));
  snprintf (url, URL_BUF_SIZE - 1, "%s%s", vault->baseurl, path);
  ctx.jwt_token = vault->token;

  char *json = devsdk_nvpairs_write (secrets);

  edgex_http_put (vault->lc, &ctx, url, json, edgex_http_write_cb, &err);
  json_free_serialized_string (json);

  if (err.code)
  {
    iot_log_error (vault->lc, "vault:error setting secrets: %s", ctx.buff);
  }
  free (ctx.buff);
}

static void vault_fini (void *impl)
{
  vault_impl_t *vault = (vault_impl_t *)impl;
  free (vault->baseurl);
  free (vault->token);
  free (impl);
}

void *edgex_secrets_vault_alloc ()
{
  return calloc (1, sizeof (vault_impl_t));
}

const edgex_secret_impls edgex_secrets_vault_fns = { vault_init, vault_reconfigure, vault_get, vault_set, vault_fini };
