/* SPDX-License-Identifier: BSD-2-Clause

  Copyright (c) 2024, Thorsten Kukuk <kukuk@suse.com>

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

  1. Redistributions of source code must retain the above copyright notice,
     this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in the
     documentation and/or other materials provided with the distribution.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE.
*/

#include "config.h"

#if HAVE_SYSTEMD

#include <stdlib.h>
#include <stdbool.h>
#include <systemd/sd-varlink.h>

#include "basics.h"
#include "varlink.h"
#include "wtmpdb.h"

/* Takes inspiration from Rust's Option::take() method: reads and returns a pointer, but at the same time
 * resets it to NULL. See: https://doc.rust-lang.org/std/option/enum.Option.html#method.take */
#define TAKE_GENERIC(var, type, nullvalue)                       \
        ({                                                       \
                type *_pvar_ = &(var);                           \
                type _var_ = *_pvar_;                            \
                type _nullvalue_ = nullvalue;                    \
                *_pvar_ = _nullvalue_;                           \
                _var_;                                           \
        })
#define TAKE_PTR_TYPE(ptr, type) TAKE_GENERIC(ptr, type, NULL)
#define TAKE_PTR(ptr) TAKE_PTR_TYPE(ptr, typeof(ptr))

static int
connect_to_wtmpdbd(sd_varlink **ret, const char *socket, char **error)
{
  _cleanup_(sd_varlink_unrefp) sd_varlink *link = NULL;
  int r;

  r = sd_varlink_connect_address(&link, socket);
  if (r < 0)
    {
      if (error)
	if (asprintf (error, "Failed to connect to %s: %s",
		      socket, strerror(-r)) < 0)
	  *error = strdup ("Out of memory");
      return r;
    }

  *ret = TAKE_PTR(link);
  return 0;
}

struct id_error {
  int64_t id;
  char *error;
};

static void
id_error_free (struct id_error *var)
{
  var->error = mfree(var->error);
}

/*
  Add new wtmp entry to db via varlink
  login timestamp is in usec.
  Returns ID (>=0)  on success, < 0 on failure.
 */
int64_t
varlink_login (int type, const char *user, uint64_t usec_login,
	       const char *tty, const char *rhost,
	       const char *service, char **error)
{
  _cleanup_(id_error_free) struct id_error p = {
    .id = -1,
    .error = NULL,
  };
  static const sd_json_dispatch_field dispatch_table[] = {
    { "ID", SD_JSON_VARIANT_INTEGER, sd_json_dispatch_int64, offsetof(struct id_error, id), 0 },
    { "ErrorMsg", SD_JSON_VARIANT_STRING, sd_json_dispatch_string,  offsetof(struct id_error, error), 0 },
    {}
  };
  _cleanup_(sd_varlink_unrefp) sd_varlink *link = NULL;
  _cleanup_(sd_json_variant_unrefp) sd_json_variant *params = NULL;
  sd_json_variant *result;
  int r;

  r = connect_to_wtmpdbd(&link, _VARLINK_WTMPDB_SOCKET_WRITER, error);
  if (r < 0)
    return r;

  r = sd_json_buildo(&params,
                     SD_JSON_BUILD_PAIR("Type", SD_JSON_BUILD_INTEGER(type)),
                     SD_JSON_BUILD_PAIR("User", SD_JSON_BUILD_STRING(user)),
		     SD_JSON_BUILD_PAIR("LoginTime", SD_JSON_BUILD_INTEGER(usec_login)));
  if (r >= 0 && tty)
    r = sd_json_variant_merge_objectbo(&params, SD_JSON_BUILD_PAIR("TTY", SD_JSON_BUILD_STRING(tty)));
  if (r >= 0 && rhost)
    r = sd_json_variant_merge_objectbo(&params, SD_JSON_BUILD_PAIR("RemoteHost", SD_JSON_BUILD_STRING(rhost)));
  if (r >= 0 && service)
    r = sd_json_variant_merge_objectbo(&params, SD_JSON_BUILD_PAIR("Service", SD_JSON_BUILD_STRING(service)));
  if (r < 0)
    {
      if (error)
	if (asprintf (error, "Failed to build JSON data: %s",
		      strerror(-r)) < 0)
	  *error = strdup ("Out of memory");
      return r;
    }

  const char *error_id;
  r = sd_varlink_call(link, "org.openSUSE.wtmpdb.Login", params, &result, &error_id);
  if (r < 0)
    {
      if (error)
	if (asprintf (error, "Failed to call Login method: %s",
		      strerror(-r)) < 0)
	  *error = strdup ("Out of memory");
      return r;
    }

  /* dispatch before checking error_id, we may need the result for the error
     message */
  r = sd_json_dispatch(result, dispatch_table, SD_JSON_ALLOW_EXTENSIONS, &p);
  if (r < 0)
    {
      if (error)
	if (asprintf (error, "Failed to parse JSON answer: %s",
		      strerror(-r)) < 0)
	  *error = strdup("Out of memory");
      return r;
    }

  if (error_id && strlen(error_id) > 0)
    {
      if (error)
	{
	  if (p.error)
	    *error = strdup(p.error);
	  else
	    *error = strdup(error_id);
	}
      return -EIO;
    }

  return p.id;
}

struct status {
  bool success;
  char *error;
};

static void
status_free (struct status *var)
{
  var->error = mfree(var->error);
}

int
varlink_logout (int64_t id, uint64_t usec_logout, char **error)
{
  _cleanup_(status_free) struct status p = {
    .success = false,
    .error = NULL,
  };
  static const sd_json_dispatch_field dispatch_table[] = {
    { "Success", SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool, offsetof(struct status, success), 0 },
    { "ErrorMsg", SD_JSON_VARIANT_STRING, sd_json_dispatch_string,  offsetof(struct status, error), 0 },
    {}
  };
  _cleanup_(sd_varlink_unrefp) sd_varlink *link = NULL;
  _cleanup_(sd_json_variant_unrefp) sd_json_variant *params = NULL;
  sd_json_variant *result;
  int r;

  r = connect_to_wtmpdbd(&link, _VARLINK_WTMPDB_SOCKET_WRITER, error);
  if (r < 0)
    return r;

  r = sd_json_buildo(&params,
                     SD_JSON_BUILD_PAIR("ID",         SD_JSON_BUILD_INTEGER(id)),
		     SD_JSON_BUILD_PAIR("LogoutTime", SD_JSON_BUILD_INTEGER(usec_logout)));
  if (r < 0)
    {
      if (error)
	if (asprintf (error, "Failed to build JSON data: %s",
		      strerror(-r)) < 0)
	  *error = strdup ("Out of memory");
      return r;
    }

  const char *error_id;
  r = sd_varlink_call(link, "org.openSUSE.wtmpdb.Logout", params, &result, &error_id);
  if (r < 0)
    {
      if (error)
	if (asprintf (error, "Failed to call Logout method: %s",
		      strerror(-r)) < 0)
	  *error = strdup ("Out of memory");
      return r;
    }

  /* dispatch before checking error_id, we may need the result for the error
     message */
  r = sd_json_dispatch(result, dispatch_table, SD_JSON_ALLOW_EXTENSIONS, &p);
  if (r < 0)
    {
      if (error)
	if (asprintf (error, "Failed to parse JSON answer: %s",
		      strerror(-r)) < 0)
	  *error = strdup("Out of memory");
      return r;
    }

  if (error_id && strlen(error_id) > 0)
    {
      if (error)
	{
	  if (p.error)
	    *error = strdup(p.error);
	  else
	    *error = strdup(error_id);
	}
      return -EIO;
    }

  return 0;
}


int64_t
varlink_get_id (const char *tty, char **error)
{
  _cleanup_(id_error_free) struct id_error p = {
    .id = -1,
    .error = NULL,
  };
  static const sd_json_dispatch_field dispatch_table[] = {
    { "ID", SD_JSON_VARIANT_INTEGER, sd_json_dispatch_int64, offsetof(struct id_error, id), 0 },
    { "ErrorMsg", SD_JSON_VARIANT_STRING, sd_json_dispatch_string,  offsetof(struct id_error, error), 0 },
    {}
  };
  _cleanup_(sd_varlink_unrefp) sd_varlink *link = NULL;
  _cleanup_(sd_json_variant_unrefp) sd_json_variant *params = NULL;
  sd_json_variant *result;
  const char *error_id;
  int r;

  r = connect_to_wtmpdbd(&link, _VARLINK_WTMPDB_SOCKET_READER, error);
  if (r < 0)
    return r;

  r = sd_json_buildo(&params, SD_JSON_BUILD_PAIR("TTY", SD_JSON_BUILD_STRING(tty)));
  if (r < 0)
    {
      if (error)
	if (asprintf (error, "Failed to build JSON data: %s",
		      strerror(-r)) < 0)
	  *error = strdup ("Out of memory");
      return r;
    }

  r = sd_varlink_call(link, "org.openSUSE.wtmpdb.GetID", params, &result, &error_id);
  if (r < 0)
    {
      if (error)
	if (asprintf (error, "Failed to call GetID method: %s",
		      strerror(-r)) < 0)
	  *error = strdup ("Out of memory");
      return r;
    }

  /* dispatch before checking error_id, we may need the result for the error
     message */
  r = sd_json_dispatch(result, dispatch_table, SD_JSON_ALLOW_EXTENSIONS, &p);
  if (r < 0)
    {
      if (error)
	if (asprintf (error, "Failed to parse JSON answer: %s",
		      strerror(-r)) < 0)
	  *error = strdup("Out of memory");
      return r;
    }

  if (error_id && strlen(error_id) > 0)
    {
      if (error)
	{
	  if (p.error)
	    *error = strdup(p.error);
	  else
	    *error = strdup(error_id);
	}
      if (strcmp(error_id, "org.openSUSE.rebootmgr.NoEntryFound") == 0)
	return -ENOENT;
      else
	return -EIO;
    }

  return p.id;
}

struct boottime {
  bool success;
  uint64_t boottime;
  char *error;
};

static void
boottime_free (struct boottime *var)
{
  var->error = mfree(var->error);
}

int
varlink_get_boottime (uint64_t *boottime, char **error)
{
  _cleanup_(boottime_free) struct boottime p = {
    .success = false,
    .boottime = -1,
    .error = NULL,
  };
  static const sd_json_dispatch_field dispatch_table[] = {
    { "Success", SD_JSON_VARIANT_BOOLEAN,  sd_json_dispatch_stdbool, offsetof(struct boottime, success), 0 },
    { "BootTime", SD_JSON_VARIANT_INTEGER, sd_json_dispatch_uint64,  offsetof(struct boottime, boottime), 0 },
    { "ErrorMsg", SD_JSON_VARIANT_STRING,  sd_json_dispatch_string,  offsetof(struct boottime, error),    0 },
    {}
  };
  _cleanup_(sd_varlink_unrefp) sd_varlink *link = NULL;
  sd_json_variant *result;
  const char *error_id;
  int r;

  r = connect_to_wtmpdbd(&link, _VARLINK_WTMPDB_SOCKET_READER, error);
  if (r < 0)
    return r;

  r = sd_varlink_call(link, "org.openSUSE.wtmpdb.GetBootTime", NULL, &result, &error_id);
  if (r < 0)
    {
      if (error)
	if (asprintf (error, "Failed to call BootTime method: %s",
		      strerror(-r)) < 0)
	  *error = strdup ("Out of memory");
      return r;
    }

  /* dispatch before checking error_id, we may need the result for the error
     message */
  r = sd_json_dispatch(result, dispatch_table, SD_JSON_ALLOW_EXTENSIONS, &p);
  if (r < 0)
    {
      if (error)
	if (asprintf (error, "Failed to parse JSON answer: %s",
		      strerror(-r)) < 0)
	  *error = strdup("Out of memory");
      return r;
    }

  if (error_id && strlen(error_id) > 0)
    {
      if (error)
	{
	  if (p.error)
	    *error = strdup(p.error);
	  else
	    *error = strdup(error_id);
	}
      if (strcmp(error_id, "org.openSUSE.rebootmgr.NoEntryFound") == 0)
	return -ENOENT;
      else
	return -EIO;
    }

  *boottime = p.boottime;
  return 0;
}

struct rotate {
  bool success;
  char *error;
  uint64_t entries;
  char *backup_name;
};

static void
rotate_free (struct rotate *var)
{
  var->backup_name = mfree(var->backup_name);
  var->error = mfree(var->error);
}

int
varlink_rotate (const int days, char **backup_name, uint64_t *entries, char **error)
{
  _cleanup_(rotate_free) struct rotate p = {
    .success = false,
    .error = NULL,
    .entries = 0,
    .backup_name = NULL
  };
  static const sd_json_dispatch_field dispatch_table[] = {
    { "Success",    SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool, offsetof(struct rotate, success), 0 },
    { "ErrorMsg",   SD_JSON_VARIANT_STRING, sd_json_dispatch_string,   offsetof(struct rotate, error), 0 },
    { "Entries",    SD_JSON_VARIANT_INTEGER, sd_json_dispatch_uint64,  offsetof(struct rotate, entries), 0 },
    { "BackupName", SD_JSON_VARIANT_STRING, sd_json_dispatch_string,   offsetof(struct rotate, backup_name), 0 },
    {}
  };
  _cleanup_(sd_varlink_unrefp) sd_varlink *link = NULL;
  _cleanup_(sd_json_variant_unrefp) sd_json_variant *params = NULL;
  sd_json_variant *result;
  int r;

  r = connect_to_wtmpdbd(&link, _VARLINK_WTMPDB_SOCKET_WRITER, error);
  if (r < 0)
    return r;

  r = sd_json_buildo(&params, SD_JSON_BUILD_PAIR("Days", SD_JSON_BUILD_INTEGER(days)));
  if (r < 0)
    {
      if (error)
	if (asprintf (error, "Failed to build JSON data: %s",
		      strerror(-r)) < 0)
	  *error = strdup ("Out of memory");
      return r;
    }

  const char *error_id;
  r = sd_varlink_call(link, "org.openSUSE.wtmpdb.Rotate", params, &result, &error_id);
  if (r < 0)
    {
      if (error)
	if (asprintf (error, "Failed to call Rotate method: %s",
		      strerror(-r)) < 0)
	  *error = strdup ("Out of memory");
      return r;
    }

  /* dispatch before checking error_id, we may need the result for the error
     message */
  r = sd_json_dispatch(result, dispatch_table, SD_JSON_ALLOW_EXTENSIONS, &p);
  if (r < 0)
    {
      if (error)
	if (asprintf (error, "Failed to parse JSON answer: %s",
		      strerror(-r)) < 0)
	  *error = strdup("Out of memory");
      return r;
    }

  if (error_id && strlen(error_id) > 0)
    {
      if (error)
	{
	  if (p.error)
	    *error = strdup(p.error);
	  else
	    *error = strdup(error_id);
	}
      return -EIO;
    }

  if (p.backup_name)
    *backup_name = strdup(p.backup_name);
  *entries = p.entries;

  return 0;
}

#endif
