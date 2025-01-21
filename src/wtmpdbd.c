//SPDX-License-Identifier: GPL-2.0-or-later

/* Copyright (c) 2024, 2025 Thorsten Kukuk
   Author: Thorsten Kukuk <kukuk@suse.com>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License along
   with this program; if not, see <http://www.gnu.org/licenses/>. */

#include "config.h"

#include <limits.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdbool.h>
#include <libintl.h>
#include <syslog.h>
#include <systemd/sd-daemon.h>
#include <systemd/sd-varlink.h>
#include <systemd/sd-journal.h>

#include "basics.h"
#include "wtmpdb.h"
#include "mkdir_p.h"

#include "varlink-org.openSUSE.wtmpdb.h"

static int log_level = LOG_WARNING;
static int socket_activation = false;

static void
set_max_log_level (int level)
{
  log_level = level;
}

static void
log_msg (int priority, const char *fmt, ...)
{
  static int is_tty = -1;

  if (priority > log_level)
    return;

  if (is_tty == -1)
    is_tty = isatty (STDOUT_FILENO);

  va_list ap;

  va_start (ap, fmt);

  if (is_tty)
    {
      if (priority <= LOG_ERR)
        {
          vfprintf (stderr, fmt, ap);
          fputc ('\n', stderr);
        }
      else
        {
          vprintf (fmt, ap);
          putchar ('\n');
        }
    }
  else
    sd_journal_printv (priority, fmt, ap);

  va_end (ap);
}

static int
vl_method_ping(sd_varlink *link, sd_json_variant *parameters,
	       sd_varlink_method_flags_t _unused_(flags),
	       void _unused_(*userdata))
{
  int r;

  log_msg (LOG_INFO, "Varlink method \"Ping\" called...");

  r = sd_varlink_dispatch(link, parameters, NULL, NULL);
  if (r != 0)
    return r;

  return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_BOOLEAN("Alive", true));
}

static int
vl_method_set_log_level(sd_varlink *link, sd_json_variant *parameters,
			sd_varlink_method_flags_t _unused_(flags),
			void _unused_(*userdata))
{
  static const sd_json_dispatch_field dispatch_table[] = {
    { "Level", SD_JSON_VARIANT_INTEGER, sd_json_dispatch_int, 0, SD_JSON_MANDATORY },
    {}
  };

  int r, level;

  log_msg(LOG_INFO, "Varlink method \"SetLogLevel\" called...");

  r = sd_varlink_dispatch(link, parameters, dispatch_table, &level);
  if (r != 0)
    return r;

  log_msg(LOG_DEBUG, "Log level %i requested", level);

  uid_t peer_uid;
  r = sd_varlink_get_peer_uid(link, &peer_uid);
  if (r < 0)
    {
      log_msg(LOG_ERR, "Failed to get peer UID: %s", strerror(-r));
      return r;
    }
  if (peer_uid != 0)
    {
      log_msg(LOG_WARNING, "SetLogLevel: peer UID %i denied", peer_uid);
      return sd_varlink_error(link, SD_VARLINK_ERROR_PERMISSION_DENIED, parameters);
    }

  set_max_log_level(level);

  log_msg (LOG_INFO, "New log setting: level=%i", level);

  return sd_varlink_reply(link, NULL);
}

static int
vl_method_get_environment(sd_varlink *link, sd_json_variant *parameters,
			  sd_varlink_method_flags_t _unused_(flags),
			  void _unused_(*userdata))
{
  int r;

  log_msg (LOG_INFO, "Varlink method \"GetEnvironment\" called...");

  r = sd_varlink_dispatch(link, parameters, NULL, NULL);
  if (r != 0)
    return r;

  uid_t peer_uid;
  r = sd_varlink_get_peer_uid(link, &peer_uid);
  if (r < 0)
    {
      log_msg(LOG_ERR, "Failed to get peer UID: %s", strerror(-r));
      return r;
    }
  if (peer_uid != 0)
    {
      log_msg(LOG_WARNING, "GetEnvironment: peer UID %i denied", peer_uid);
      return sd_varlink_error(link, SD_VARLINK_ERROR_PERMISSION_DENIED, parameters);
    }

#if 0 /* XXX */
  for (char **e = environ; *e != 0; e++)
    {
      if (!env_assignment_is_valid(*e))
	goto invalid;
      if (!utf8_is_valid(*e))
	goto invalid;
    }
#endif

  return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_STRV("Environment", environ));

#if 0
 invalid:
  return sd_varlink_error(link, "io.systemd.service.InconsistentEnvironment", parameters);
#endif
}

struct login_record {
  int type;
  char *user;
  uint64_t usec_login;
  char *tty;
  char *rhost;
  char *service;
};

static void
login_record_free (struct login_record *var)
{
  var->user = mfree(var->user);
  var->tty = mfree(var->tty);
  var->rhost = mfree(var->rhost);
  var->service = mfree(var->service);
}

static int
vl_method_login(sd_varlink *link, sd_json_variant *parameters,
		sd_varlink_method_flags_t _unused_(flags),
		void _unused_(*userdata))
{
  _cleanup_(freep) char *error = NULL;
  _cleanup_(login_record_free) struct login_record p = {
    .type = -1,
    .user = NULL,
    .usec_login = 0,
    .tty = NULL,
    .rhost = NULL,
    .service = NULL,
  };
  static const sd_json_dispatch_field dispatch_table[] = {
    { "Type",       SD_JSON_VARIANT_INTEGER, sd_json_dispatch_int,     offsetof(struct login_record, type),       SD_JSON_MANDATORY },
    { "User",       SD_JSON_VARIANT_STRING,  sd_json_dispatch_string,  offsetof(struct login_record, user),       SD_JSON_MANDATORY },
    { "LoginTime",  SD_JSON_VARIANT_INTEGER, sd_json_dispatch_uint64,  offsetof(struct login_record, usec_login), SD_JSON_MANDATORY },
    { "TTY",        SD_JSON_VARIANT_STRING,  sd_json_dispatch_string,  offsetof(struct login_record, tty),        0 },
    { "RemoteHost", SD_JSON_VARIANT_STRING,  sd_json_dispatch_string,  offsetof(struct login_record, rhost),      0 },
    { "Service",    SD_JSON_VARIANT_STRING,  sd_json_dispatch_string,  offsetof(struct login_record, service),    0 },
    {}
  };
  int64_t id = -1;
  int r;

  log_msg (LOG_INFO, "Varlink method \"Login\" called...");

  r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
  if (r != 0)
    {
      log_msg(LOG_ERR, "Login method: varlink dispatch failed: %s", strerror (-r));
      return r;
    }

  log_msg(LOG_DEBUG, "Requested login record: %i, %s, %li, %s, %s, %s",
	  p.type, p.user, p.usec_login, p.tty, p.rhost, p.service);

  uid_t peer_uid;
  r = sd_varlink_get_peer_uid(link, &peer_uid);
  if (r < 0)
    {
      log_msg(LOG_ERR, "Failed to get peer UID: %s", strerror(-r));
      return r;
    }
  if (peer_uid != 0)
    {
      log_msg(LOG_WARNING, "Login: peer UID %i denied", peer_uid);
      return sd_varlink_error(link, SD_VARLINK_ERROR_PERMISSION_DENIED, parameters);
    }

  id = wtmpdb_login (_PATH_WTMPDB, p.type, p.user, p.usec_login, p.tty, p.rhost, p.service, &error);
  if (id < 0 || error != NULL)
    {
      log_msg(LOG_ERR, "Get ID request from db failed: %s", error);
      return sd_varlink_errorbo(link, "org.openSUSE.rebootmgr.InternalError",
				SD_JSON_BUILD_PAIR_STRING("ErrorMsg", error));
    }

  return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_INTEGER("ID", id));
}

static int
vl_method_logout(sd_varlink *link, sd_json_variant *parameters,
		 sd_varlink_method_flags_t _unused_(flags),
		 void _unused_(*userdata))
{
  struct p {
    int64_t id;
    uint64_t usec_logout;
  } p = {
    .id = -1,
    .usec_logout = 0,
  };
  static const sd_json_dispatch_field dispatch_table[] = {
    { "ID",         SD_JSON_VARIANT_INTEGER, sd_json_dispatch_int64, offsetof(struct p, id),           SD_JSON_MANDATORY },
    { "LogoutTime", SD_JSON_VARIANT_INTEGER, sd_json_dispatch_uint64, offsetof(struct p, usec_logout), SD_JSON_MANDATORY },
    {}
  };
  _cleanup_(freep) char *error = NULL;
  int64_t id = -1;
  int r;

  log_msg (LOG_INFO, "Varlink method \"Logout\" called...");

  r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
  if (r != 0)
    {
      log_msg(LOG_ERR, "Logout request: varlink dispatch failed: %s", strerror (-r));
      return r;
    }

  log_msg(LOG_DEBUG, "Logout for entry '%li' at time '%lu' requested", p.id, p.usec_logout);

  uid_t peer_uid;
  r = sd_varlink_get_peer_uid(link, &peer_uid);
  if (r < 0)
    {
      log_msg(LOG_ERR, "Failed to get peer UID: %s", strerror(-r));
      return r;
    }
  if (peer_uid != 0)
    {
      log_msg(LOG_WARNING, "Logout: peer UID %i denied", peer_uid);
      return sd_varlink_error(link, SD_VARLINK_ERROR_PERMISSION_DENIED, parameters);
    }

  id = wtmpdb_logout (_PATH_WTMPDB, p.id, p.usec_logout, &error);
  if (id < 0 || error != NULL)
    {
      /* let wtmpdb_logout return better error codes, e.g. not found vs real error */
      log_msg(LOG_ERR, "Logout request from db failed: %s", error);
      return sd_varlink_errorbo(link, "org.openSUSE.rebootmgr.InternalError",
				SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
                                SD_JSON_BUILD_PAIR_STRING("ErrorMsg", error));

    }

  return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_BOOLEAN("Success", true));
}

struct get_id {
  char *tty;
};

static void
get_id_free (struct get_id *var)
{
  var->tty = mfree(var->tty);
}

static int
vl_method_get_id(sd_varlink *link, sd_json_variant *parameters,
		 sd_varlink_method_flags_t _unused_(flags),
		 void _unused_(*userdata))
{
  _cleanup_(get_id_free) struct get_id p = {
    .tty = NULL,
  };
  static const sd_json_dispatch_field dispatch_table[] = {
    { "TTY", SD_JSON_VARIANT_STRING, sd_json_dispatch_string, offsetof(struct get_id, tty), SD_JSON_MANDATORY },
    {}
  };
  _cleanup_(freep) char *error = NULL;
  int64_t id = -1;
  int r;

  log_msg (LOG_INFO, "Varlink method \"GetID\" called...");

  r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
  if (r != 0)
    {
      log_msg(LOG_ERR, "Get ID request: varlink dispatch failed: %s", strerror (-r));
      return r;
    }

  log_msg(LOG_DEBUG, "ID for entry on tty '%s' requested", p.tty);

  id = wtmpdb_get_id (_PATH_WTMPDB, p.tty, &error);
  if (id < 0 || error != NULL)
    {
      log_msg(LOG_ERR, "Get ID request from db failed: %s", error);
      return sd_varlink_errorbo(link, "org.openSUSE.rebootmgr.NoEntryFound",
                                SD_JSON_BUILD_PAIR_STRING("ErrorMsg", error));

    }

  return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_INTEGER("ID", id));
}

static int
vl_method_get_boottime(sd_varlink *link, sd_json_variant *parameters,
		       sd_varlink_method_flags_t _unused_(flags),
		       void _unused_(*userdata))
{
  static const sd_json_dispatch_field dispatch_table[] = {
    {}
  };
  _cleanup_(freep) char *error = NULL;
  uint64_t boottime = 0;
  int r;

  log_msg (LOG_INFO, "Varlink method \"GetBootTime\" called...");

  r = sd_varlink_dispatch(link, parameters, dispatch_table, /* userdata= */ NULL);
  if (r != 0)
    {
      log_msg(LOG_ERR, "Get boottime request: varlink dispatch failed: %s", strerror (-r));
      return r;
    }

  boottime = wtmpdb_get_boottime (_PATH_WTMPDB, &error);
  if (boottime == 0 || error != NULL)
    {
      log_msg(LOG_ERR, "Get boottime from db failed: %s", error);
      return sd_varlink_errorbo(link, "org.openSUSE.rebootmgr.NoEntryFound",
				SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
                                SD_JSON_BUILD_PAIR_STRING("ErrorMsg", error));

    }

  return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_BOOLEAN("Success", true),
			    SD_JSON_BUILD_PAIR_INTEGER("BootTime", boottime));
}

static int incomplete = 0;

static int
wtmpdb_cb_func (void *u, int argc, char **argv, char _unused_(**azColName))
{
  sd_json_variant **array = u;
  char *endptr;
  uint64_t logout_t = 0;
  int r;

  log_msg(LOG_DEBUG, "wtmpdb_cb_func called for ID %s", argv[0]);

  if (argc != 8)
    {
      log_msg(LOG_ERR, "Invalid number of arguments: got %i, expected 8", argc);
      incomplete = 1;
      return 0;
    }

  const int id = atoi (argv[0]);
  const int type = atoi (argv[1]);
  const char *user = argv[2];
  const char *tty = argv[5]?argv[5]:"?";
  const char *host = argv[6]?argv[6]:"";
  const char *service = argv[7]?argv[7]:"";
  uint64_t login_t = strtoull(argv[3], &endptr, 10);
  if ((errno == ERANGE && login_t == ULLONG_MAX)
      || (endptr == argv[3]) || (*endptr != '\0'))
    {
      log_msg(LOG_ERR, "Invalid numeric time entry for 'login': '%s'\n", argv[3]);
      incomplete = 1;
      return 0;
    }
  if (argv[4])
    {
      logout_t = strtoull(argv[4], &endptr, 10);
      if ((errno == ERANGE && logout_t == ULLONG_MAX)
          || (endptr == argv[4]) || (*endptr != '\0'))
	{
	  log_msg(LOG_ERR, "Invalid numeric time entry for 'logout': '%s'\n", argv[4]);
	  incomplete = 1;
	  return 0;
	}
    }

  log_msg(LOG_DEBUG, "ID: %i, Type: %i, User: %s, Login: %lu, Logout: %lu, TTY: %s, RemoteHost: %s, Service: %s",
	  id, type, user, login_t, logout_t, tty, host, service);

  r = sd_json_variant_append_arraybo(array,
				     SD_JSON_BUILD_PAIR_INTEGER("ID", id),
				     SD_JSON_BUILD_PAIR_INTEGER("Type", type),
				     SD_JSON_BUILD_PAIR_STRING("User", user),
				     SD_JSON_BUILD_PAIR_INTEGER("Login", login_t),
				     SD_JSON_BUILD_PAIR_INTEGER("Logout", logout_t),
				     SD_JSON_BUILD_PAIR_STRING("TTY", tty),
				     SD_JSON_BUILD_PAIR_STRING("RemoteHost", host),
				     SD_JSON_BUILD_PAIR_STRING("Service", service));
  if (r < 0)
    {
      log_msg(LOG_ERR, "Appending array failed: %s", strerror(-r));
      incomplete = 1;
    }

  return 0;
}



static int
vl_method_read_all(sd_varlink *link, sd_json_variant *parameters,
		   sd_varlink_method_flags_t _unused_(flags),
		   void _unused_(*userdata))
{
  _cleanup_(sd_json_variant_unrefp) sd_json_variant *array = NULL;
  static const sd_json_dispatch_field dispatch_table[] = {
    {}
  };
  _cleanup_(freep) char *error = NULL;
  int r;

  log_msg (LOG_INFO, "Varlink method \"ReadAll\" called...");

  r = sd_varlink_dispatch(link, parameters, dispatch_table, /* userdata= */ NULL);
  if (r != 0)
    {
      log_msg(LOG_ERR, "Get all entries request: varlink dispatch failed: %s", strerror (-r));
      return r;
    }

  incomplete = 0;
  r = wtmpdb_read_all_v2 (_PATH_WTMPDB, &wtmpdb_cb_func, (void *)&array, &error);
  if (r < 0 || error != NULL || incomplete)
    {
      log_msg(LOG_ERR, "Didn't got all entries from db: %s", error);
      return sd_varlink_errorbo(link, "org.openSUSE.rebootmgr.InternalError",
				SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
                                SD_JSON_BUILD_PAIR_STRING("ErrorMsg", error?error:"unknown"));

    }

  return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_BOOLEAN("Success", true),
			    SD_JSON_BUILD_PAIR_VARIANT("Data", array));
}

static int
vl_method_rotate(sd_varlink *link, sd_json_variant *parameters,
		 sd_varlink_method_flags_t _unused_(flags),
		 void _unused_(*userdata))
{
  struct p {
    int days;
  } p = {
    .days = -1
  };
  static const sd_json_dispatch_field dispatch_table[] = {
    { "Days", SD_JSON_VARIANT_INTEGER, sd_json_dispatch_int, offsetof(struct p, days), SD_JSON_MANDATORY },
    {}
  };
  _cleanup_(freep) char *error = NULL;
  int r;

  log_msg (LOG_INFO, "Varlink method \"Rotate\" called...");

  r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
  if (r != 0)
    {
      log_msg(LOG_ERR, "Rotate request: varlink dispatch failed: %s", strerror (-r));
      return r;
    }

  log_msg(LOG_DEBUG, "Rotate of database for entries older than '%i' days requested", p.days);

  uid_t peer_uid;
  r = sd_varlink_get_peer_uid(link, &peer_uid);
  if (r < 0)
    {
      log_msg(LOG_ERR, "Failed to get peer UID: %s", strerror(-r));
      return r;
    }
  if (peer_uid != 0)
    {
      log_msg(LOG_WARNING, "Rotate: peer UID %i denied", peer_uid);
      return sd_varlink_error(link, SD_VARLINK_ERROR_PERMISSION_DENIED, parameters);
    }

  _cleanup_(freep) char *backup = NULL;
  uint64_t entries = 0;
  r = wtmpdb_rotate (_PATH_WTMPDB, p.days, &error, &backup, &entries);
  if (r < 0 || error != NULL)
    {
      log_msg(LOG_ERR, "Rotate db failed: %s", error);
      return sd_varlink_errorbo(link, "org.openSUSE.rebootmgr.NoEntryFound",
				SD_JSON_BUILD_PAIR_BOOLEAN("Success", false),
                                SD_JSON_BUILD_PAIR_STRING("ErrorMsg", error));
    }

  /* XXX make this nicer, build reply on demand */
  if (backup)
    return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_BOOLEAN("Success", true),
			      SD_JSON_BUILD_PAIR_STRING("BackupName", backup),
			      SD_JSON_BUILD_PAIR_INTEGER("Entries", entries));
  else
    return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_BOOLEAN("Success", true),
			      SD_JSON_BUILD_PAIR_INTEGER("Entries", entries));
}

static int
vl_method_quit (sd_varlink *link, sd_json_variant *parameters,
		  sd_varlink_method_flags_t _unused_(flags),
		  void *userdata)
{
  struct p {
    int code;
  } p = {
    .code = 0
  };
  static const sd_json_dispatch_field dispatch_table[] = {
    { "ExitCode", SD_JSON_VARIANT_INTEGER, sd_json_dispatch_int, offsetof(struct p, code), 0 },
    {}
  };
  sd_event *loop = userdata;
  int r;

  log_msg (LOG_INFO, "Varlink method \"Quit\" called...");

  r = sd_varlink_dispatch (link, parameters, dispatch_table, /* userdata= */ NULL);
  if (r != 0)
    {
      log_msg (LOG_ERR, "Quit request: varlink dispatch failed: %s", strerror (-r));
      return r;
    }

  uid_t peer_uid;
  r = sd_varlink_get_peer_uid(link, &peer_uid);
  if (r < 0)
    {
      log_msg(LOG_ERR, "Failed to get peer UID: %s", strerror(-r));
      return r;
    }
  if (peer_uid != 0)
    {
      log_msg(LOG_WARNING, "Quit: peer UID %i denied", peer_uid);
      return sd_varlink_error(link, SD_VARLINK_ERROR_PERMISSION_DENIED, parameters);
    }

  r = sd_event_exit (loop, p.code);
  if (r != 0)
    {
      log_msg (LOG_ERR, "Quit request: disabling event loop failed: %s",
	       strerror (-r));
      return sd_varlink_errorbo(link, "org.openSUSE.wtmpdb.InternalError",
                                SD_JSON_BUILD_PAIR_BOOLEAN("Success", false));
    }

  return sd_varlink_replybo (link, SD_JSON_BUILD_PAIR_BOOLEAN("Success", true));
}

/* Send a messages to systemd daemon, that inicialization of daemon
   is finished and daemon is ready to accept connections. */
static void
announce_ready (void)
{
  int r = sd_notify (0, "READY=1\n"
		     "STATUS=Processing requests...");
  if (r < 0)
    log_msg (LOG_ERR, "sd_notify(READY) failed: %s", strerror(-r));
}

static void
announce_stopping (void)
{
  int r = sd_notify (0, "STOPPING=1\n"
		     "STATUS=Shutting down...");
  if (r < 0)
    log_msg (LOG_ERR, "sd_notify(STOPPING) failed: %s", strerror(-r));
}

/* event loop which quits after 30 seconds idle time */
#define DEFAULT_EXIT_USEC (30*USEC_PER_SEC)

static int
varlink_event_loop_with_idle(sd_event *e, sd_varlink_server *s)
{
  int r, code;

  for (;;)
    {
      r = sd_event_get_state(e);
      if (r < 0)
	return r;
      if (r == SD_EVENT_FINISHED)
	break;

      r = sd_event_run(e, DEFAULT_EXIT_USEC);
      if (r < 0)
	return r;

      if (r == 0 && (sd_varlink_server_current_connections(s) == 0))
	sd_event_exit(e, 0);
    }

  r = sd_event_get_exit_code(e, &code);
  if (r < 0)
    return r;

  return code;
}

static int
run_varlink (void)
{
  int r;
  _cleanup_(sd_event_unrefp) sd_event *event = NULL;
  _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *varlink_server = NULL;

  r = mkdir_p(_VARLINK_WTMPDB_SOCKET_DIR, 0755);
  if (r < 0)
    {
      log_msg(LOG_ERR, "Failed to create directory '"_VARLINK_WTMPDB_SOCKET_DIR"' for Varlink socket: %s",
	      strerror(-r));
      return r;
    }

  r = sd_event_new (&event);
  if (r < 0)
    {
      log_msg (LOG_ERR, "Failed to create new event: %s",
	       strerror (-r));
      return r;
    }

  r = sd_varlink_server_new (&varlink_server, SD_VARLINK_SERVER_ACCOUNT_UID|SD_VARLINK_SERVER_INHERIT_USERDATA);
  if (r < 0)
    {
      log_msg (LOG_ERR, "Failed to allocate varlink server: %s",
	       strerror (-r));
      return r;
    }

  r = sd_varlink_server_set_description (varlink_server, "wtmpdbd");
  if (r < 0)
    {
      log_msg (LOG_ERR, "Failed to set varlink server description: %s",
	       strerror (-r));
      return r;
    }

  r = sd_varlink_server_set_info (varlink_server, NULL, PACKAGE" (wtmpdbd)",
				  VERSION, "https://github.com/thkukuk/wtmpdb");
  if (r < 0)
    return r;

  r = sd_varlink_server_add_interface (varlink_server, &vl_interface_org_openSUSE_wtmpdb);
  if (r < 0)
    {
      log_msg(LOG_ERR, "Failed to add interface: %s", strerror(-r));
      return r;
    }

  r = sd_varlink_server_bind_method_many (varlink_server,
					  "org.openSUSE.wtmpdb.GetBootTime",    vl_method_get_boottime,
					  "org.openSUSE.wtmpdb.GetEnvironment", vl_method_get_environment,
					  "org.openSUSE.wtmpdb.GetID",          vl_method_get_id,
					  "org.openSUSE.wtmpdb.Login",          vl_method_login,
					  "org.openSUSE.wtmpdb.Logout",         vl_method_logout,
					  "org.openSUSE.wtmpdb.Ping",           vl_method_ping,
					  "org.openSUSE.wtmpdb.Quit",           vl_method_quit,
					  "org.openSUSE.wtmpdb.ReadAll",        vl_method_read_all,
					  "org.openSUSE.wtmpdb.Rotate",         vl_method_rotate,
					  "org.openSUSE.wtmpdb.SetLogLevel",    vl_method_set_log_level);
  if (r < 0)
    {
      log_msg(LOG_ERR, "Failed to bind Varlink methods: %s",
	      strerror(-r));
      return r;
    }

  sd_varlink_server_set_userdata (varlink_server, event);

  r = sd_varlink_server_attach_event (varlink_server, event, SD_EVENT_PRIORITY_NORMAL);
  if (r < 0)
    {
      log_msg (LOG_ERR, "Failed to attach to event: %s", strerror (-r));
      return r;
    }

  r = sd_varlink_server_listen_auto (varlink_server);
  if (r < 0)
    {
      log_msg (LOG_ERR, "Failed to listens: %s", strerror (-r));
      return r;
    }


  if (!socket_activation)
    {
      r = sd_varlink_server_listen_address(varlink_server, _VARLINK_WTMPDB_SOCKET, 0666);
      if (r < 0)
	{
	  log_msg (LOG_ERR, "Failed to bind to Varlink socket: %s", strerror (-r));
	  return r;
	}
    }

  announce_ready();
  if (socket_activation)
    r = varlink_event_loop_with_idle(event, varlink_server);
  else
    r = sd_event_loop(event);
  announce_stopping();

  return r;
}

static void
print_help (void)
{
  printf("wtmpdbd - manage wtmpdb\n");

  printf("  -s, --socket   Activation through socket\n");
  printf("  -d, --debug    Debug mode\n");
  printf("  -v, --verbose  Verbose logging\n");
  printf("  -?, --help     Give this help list\n");
  printf("      --version  Print program version\n");
}

int
main (int argc, char **argv)
{
  while (1)
    {
      int c;
      int option_index = 0;
      static struct option long_options[] =
        {
	  {"socket", no_argument, NULL, 's'},
          {"debug", no_argument, NULL, 'd'},
          {"verbose", no_argument, NULL, 'v'},
          {"version", no_argument, NULL, '\255'},
          {"usage", no_argument, NULL, '?'},
          {"help", no_argument, NULL, 'h'},
          {NULL, 0, NULL, '\0'}
        };


      c = getopt_long (argc, argv, "sdvh?", long_options, &option_index);
      if (c == (-1))
        break;
      switch (c)
        {
	case 's':
	  socket_activation = true;
	  break;
        case 'd':
	  set_max_log_level(LOG_DEBUG);
          break;
        case '?':
        case 'h':
          print_help ();
          return 0;
        case 'v':
	  set_max_log_level(LOG_INFO);
          break;
        case '\255':
          fprintf (stdout, "wtmpdbd (%s) %s\n", PACKAGE, VERSION);
          return 0;
        default:
          print_help ();
          return 1;
        }
    }

  argc -= optind;
  argv += optind;

  if (argc > 1)
    {
      fprintf (stderr, "Try `wtmpdbd --help' for more information.\n");
      return 1;
    }

  log_msg (LOG_INFO, "Starting wtmpdbd (%s) %s...", PACKAGE, VERSION);

  int r = run_varlink ();
  if (r < 0)
    {
      log_msg (LOG_ERR, "ERROR: varlink loop failed: %s", strerror (-r));
      return -r;
    }

  log_msg (LOG_INFO, "wtmpdbd stopped.");

  return 0;
}
