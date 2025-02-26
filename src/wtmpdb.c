/* SPDX-License-Identifier: BSD-2-Clause

  Copyright (c) 2023, Thorsten Kukuk <kukuk@suse.com>

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

#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <getopt.h>
#include <netdb.h>
#include <inttypes.h>
#include <arpa/inet.h>
#include <sys/utsname.h>

#if HAVE_AUDIT
#include <libaudit.h>
#endif

#if HAVE_SYSTEMD
#include <systemd/sd-bus.h>
#define _cleanup_(f) __attribute__((cleanup(f)))
#endif

#include "import.h"
#include "wtmpdb.h"

static char *wtmpdb_path = NULL;

#define TIMEFMT_CTIME  1
#define TIMEFMT_SHORT  2
#define TIMEFMT_HHMM   3
#define TIMEFMT_NOTIME 4
#define TIMEFMT_ISO    5

#define TIMEFMT_VALUE 255

#define LOGROTATE_DAYS 60

/* lenght of login string cannot become longer */
#define LAST_TIMESTAMP_LEN 32

static uint64_t wtmp_start = UINT64_MAX;
static int after_reboot = 0;

/* options for last */
static int hostlast = 0;
static int nohostname = 0;
static int noservice = 1;
static int dflag = 0;
static int iflag = 0;
static int jflag = 0;
static int wflag = 0;
static int xflag = 0;
static const int name_len = 8; /* LAST_LOGIN_LEN */
static int login_fmt = TIMEFMT_SHORT;
static int login_len = 16; /* 16 = short, 24 = full */
static int logout_fmt = TIMEFMT_HHMM;
static int logout_len = 5; /* 5 = short, 24 = full */
static const int host_len = 16; /* LAST_DOMAIN_LEN */
static unsigned long maxentries = 0; /* max number of entries to show */
static unsigned long currentry = 0; /* number of entries already printed */
static time_t present = 0; /* Who was present at the specified time */
static time_t since = 0; /* Who was logged in after this time? */
static time_t until = 0; /* Who was logged in until this time? */
static char **match = NULL; /* user/tty to display only */


/* isipaddr - find out if string provided is an IP address or not
   0 - no IP address
   1 - is IP address
*/
static int
isipaddr (const char *string, int *addr_type,
          struct sockaddr_storage *addr)
{
  struct sockaddr_storage local_addr;
  int is_ip;

  if (addr == NULL)
    addr = &local_addr;

  memset(addr, 0, sizeof (struct sockaddr_storage));

  /* first ipv4 */
  if (inet_pton (AF_INET, string, &((struct sockaddr_in *)addr)->sin_addr) > 0)
    {
      if (addr_type != NULL)
        *addr_type = AF_INET;
      addr->ss_family = AF_INET;
      is_ip = 1;
    }
  else if (inet_pton (AF_INET6, string, &((struct sockaddr_in6 *)addr)->sin6_addr) > 0)
    { /* then ipv6 */
      if (addr_type != NULL)
        *addr_type = AF_INET6;
      addr->ss_family = AF_INET6;
      is_ip = 1;
    }
  else
    is_ip = 0;

  return is_ip;
}

static int
parse_time (const char *str, time_t *arg)
{
  struct tm res = { 0 };

  if (strcmp (str, "today") == 0)
    {
      time_t t = time (NULL);
      localtime_r (&t, &res);
      res.tm_isdst = -1;
      res.tm_sec = res.tm_min = res.tm_hour = 0;
    }
  else if (strcmp (str, "yesterday") == 0)
    {
      time_t t = time (NULL);
      localtime_r (&t, &res);
      res.tm_isdst = -1;
      res.tm_mday--;
      res.tm_sec = res.tm_min = res.tm_hour = 0;
    }
  else
    {
      char *r = strptime (str, "%Y-%m-%d %T",  &res);

      if (r == NULL || *r != '\0')
	{
	  r = strptime (str, "%Y-%m-%d",  &res);
	  if (r == NULL || *r != '\0')
	    return -1;
	}
    }

  *arg = mktime (&res);

  return 0;
}

static int
time_format (const char *fmt)
{
  if (strcmp (fmt, "notime") == 0)
    {
      login_fmt = TIMEFMT_NOTIME;
      login_len = 0;
      logout_fmt = TIMEFMT_NOTIME;
      logout_len = 0;
      return TIMEFMT_NOTIME;
    }
  if (strcmp (fmt, "short") == 0)
    {
      login_fmt = TIMEFMT_SHORT;
      login_len = 16;
      logout_fmt = TIMEFMT_HHMM;
      logout_len = 5;
      return TIMEFMT_SHORT;
    }
  if (strcmp (fmt, "full") == 0)
   {
     login_fmt = TIMEFMT_CTIME;
     login_len = 24;
     logout_fmt = TIMEFMT_CTIME;
     logout_len = 24;
     return TIMEFMT_CTIME;
   }
  if (strcmp (fmt, "iso") == 0)
   {
     login_fmt = TIMEFMT_ISO;
     login_len = 25;
     logout_fmt = TIMEFMT_ISO;
     logout_len = 25;
     return TIMEFMT_ISO;
   }

  return -1;
}

static void
format_time (int fmt, char *dst, size_t dstlen, uint64_t time)
{
  switch (fmt)
    {
    case TIMEFMT_CTIME:
      {
	time_t t = (time_t)time;
	snprintf (dst, dstlen, "%s", ctime (&t));
	dst[strlen (dst)-1] = '\0'; /* Remove trailing '\n' */
	break;
      }
    case TIMEFMT_SHORT:
      {
	time_t t = (time_t)time;
	struct tm *tm = localtime (&t);
	strftime (dst, dstlen, "%a %b %e %H:%M", tm);
	break;
      }
    case TIMEFMT_HHMM:
      {
	time_t t = (time_t)time;
	struct tm *tm = localtime (&t);
	strftime (dst, dstlen, "%H:%M", tm);
	break;
      }
    case TIMEFMT_ISO:
      {
	time_t t = (time_t)time;
	struct tm *tm = localtime (&t);
	strftime (dst, dstlen, "%FT%T%z", tm); /* Same ISO8601 format original last command uses */
	break;
      }
    case TIMEFMT_NOTIME:
      *dst = '\0';
      break;
    default:
      abort ();
    }
}

static void
calc_time_length(char *dst, size_t dstlen, uint64_t start, uint64_t stop)
{
  uint64_t secs = (stop - start)/USEC_PER_SEC;
  int mins  = (secs / 60) % 60;
  int hours = (secs / 3600) % 24;
  uint64_t days  = secs / 86400;

  if (days)
    snprintf (dst, dstlen, "(%" PRId64 "+%02d:%02d)", days, hours, mins);
  else if (hours)
    snprintf (dst, dstlen, " (%02d:%02d)", hours, mins);
  else
    snprintf (dst, dstlen, " (00:%02d)", mins);
}

/* map "soft-reboot" to "s-reboot" if we have only 8 characters
   for user output (no -w specified) */
static const char *
map_soft_reboot (const char *user)
{
  if (wflag || strcmp (user, "soft-reboot") != 0)
    return user;

  if ((int)strlen (user) > name_len)
    return "s-reboot";

  return user;
}

static const char *
remove_parentheses(const char *str)
{

  static char buf[LAST_TIMESTAMP_LEN];

  if (strlen(str) >= LAST_TIMESTAMP_LEN)
    return str;

  char *cp = strchr (str, '(');

  if (cp == NULL)
    return str;

  cp++;
  strncpy(buf, cp, LAST_TIMESTAMP_LEN);

  cp = strchr (buf, ')');
  if (cp)
    *cp = '\0';

  return buf;
}

static int first_entry = 1;
static void
print_line (const char *user, const char *tty, const char *host,
	    const char *print_service,
	    const char *logintime, const char *logouttime,
	    const char *length)
{
  if (jflag)
    {
      if (first_entry)
	first_entry = 0;
      else
	printf (",\n");
      printf ("     { \"user\": \"%s\",\n", user);
      printf ("       \"tty\": \"%s\",\n", tty);
      if (!nohostname)
	printf ("       \"hostname\": \"%s\",\n", host);
      if (print_service && strlen (print_service) > 0)
	printf ("       \"service\": \"%s\",\n", print_service);
      printf ("       \"login\": \"%s\",\n", logintime);
      if (length[0] == ' ' || length[0] == '(')
	{
	  printf ("       \"logout\": \"%s\",\n", logouttime);
	  printf ("       \"length\": \"%s\"\n",  remove_parentheses(length));
	}
      else
	printf ("       \"logout\": \"%s %s\"\n", logouttime, length);
      printf ("     }");
    }
  else
    {
      char *line;

      if (nohostname)
	{
	  if (asprintf (&line, "%-8.*s %-12.12s%s %-*.*s - %-*.*s %s\n",
			wflag?(int)strlen (user):name_len,
			map_soft_reboot (user), tty, print_service,
			login_len, login_len, logintime,
			logout_len, logout_len, logouttime,
			length) < 0)
	    {
	      fprintf (stderr, "Out f memory");
	      exit (EXIT_FAILURE);
	    }
	}
      else
	{
	  if (hostlast)
	    {
	      if (asprintf (&line, "%-8.*s %-12.12s%s %-*.*s - %-*.*s %-12.12s %s\n",
			    wflag?(int)strlen(user):name_len, map_soft_reboot (user),
			    tty, print_service,
			    login_len, login_len, logintime,
			    logout_len, logout_len, logouttime,
			    length, host) < 0)
		{
		  fprintf (stderr, "Out f memory");
		  exit (EXIT_FAILURE);
		}
	    }
	  else
	    {
	      if (asprintf (&line, "%-8.*s %-12.12s %-16.*s%s %-*.*s - %-*.*s %s\n",
			    wflag?(int)strlen(user):name_len, map_soft_reboot (user), tty,
			    wflag?(int)strlen(host):host_len, host, print_service,
			    login_len, login_len, logintime,
			    logout_len, logout_len, logouttime,
			    length) < 0)
		{
		  fprintf (stderr, "Out f memory");
		  exit (EXIT_FAILURE);
		}
	    }
	}

      printf ("%s", line);
      free (line);
    }
}

static int
print_entry (void *unused __attribute__((__unused__)),
	     int argc, char **argv, char **azColName)
{
  char host_buf[NI_MAXHOST];
  char logintime[32]; /* LAST_TIMESTAMP_LEN */
  char logouttime[32]; /* LAST_TIMESTAMP_LEN */
  char length[32]; /* LAST_TIMESTAMP_LEN */
  char *endptr;
  uint64_t logout_t = 0;
  static uint64_t newer_boot = 0;

  /* Yes, it's waste of time to let sqlite iterate through all entries
     even if we don't need more anymore, but telling sqlite we don't
     want more leads to a "query aborted" error... */
  if (maxentries && currentry >= maxentries)
    return 0;

  /* ID, Type, User, LoginTime, LogoutTime, TTY, RemoteHost, Service */
  if (argc != 8)
    {
      fprintf (stderr, "Mangled entry:");
      for (int i = 0; i < argc; i++)
        fprintf (stderr, " %s=%s", azColName[i], argv[i] ? argv[i] : "NULL");
      fprintf (stderr, "\n");
      exit (EXIT_FAILURE);
    }

  const int type = atoi (argv[1]);
  const char *user = argv[2];
  const char *tty = argv[5]?argv[5]:"?";
  const char *host = argv[6]?argv[6]:"";
  const char *service = argv[7]?argv[7]:"";

  uint64_t login_t = strtoull(argv[3], &endptr, 10);
  if ((errno == ERANGE && login_t == ULLONG_MAX)
      || (endptr == argv[3]) || (*endptr != '\0'))
    fprintf (stderr, "Invalid numeric time entry for 'login': '%s'\n",
	     argv[3]);

  if (login_t < wtmp_start)
    wtmp_start = login_t;

  if (since && (since > (time_t)(login_t/USEC_PER_SEC)))
    return 0;

  if (until && (until < (time_t)(login_t/USEC_PER_SEC)))
    return 0;

  if (present && (present < (time_t)(login_t/USEC_PER_SEC)))
    return 0;

  if (match)
    {
      char **walk;

      for (walk = match; *walk; walk++)
	{
	  if (strcmp (user, *walk) == 0 ||
	      strcmp(tty, *walk) == 0)
	    break;
	}
      if (*walk == NULL)
	return 0;
    }

  format_time (login_fmt, logintime, sizeof (logintime),
	       login_t/USEC_PER_SEC);

  if (argv[4])
    {
      logout_t = strtoull(argv[4], &endptr, 10);
      if ((errno == ERANGE && logout_t == ULLONG_MAX)
	  || (endptr == argv[4]) || (*endptr != '\0'))
	fprintf (stderr, "Invalid numeric time entry for 'logout': '%s'\n",
		 argv[4]);

      if (present && (0 < (logout_t/USEC_PER_SEC)) &&
	  ((time_t)(logout_t/USEC_PER_SEC) < present))
	return 0;

      format_time (logout_fmt, logouttime, sizeof (logouttime),
		   logout_t/USEC_PER_SEC);

      calc_time_length (length, sizeof(length), login_t, logout_t);
    }
  else /* login but no logout */
    {
      if (after_reboot)
	{
	  snprintf (logouttime, sizeof (logouttime), "crash");
	  length[0] = '\0';
	}
      else
	{
	  switch (type)
	    {
	    case USER_PROCESS:
	      if (logout_fmt == TIMEFMT_HHMM)
		{
		  snprintf (logouttime, sizeof (logouttime), "still");
		  snprintf(length, sizeof(length), "logged in");
		}
	      else
		{
		  snprintf (logouttime, sizeof (logouttime), "still logged in");
		  length[0] = '\0';
		}
	      break;
	    case BOOT_TIME:
	      if (logout_fmt == TIMEFMT_HHMM)
		{
		  snprintf (logouttime, sizeof (logouttime), "still");
		  snprintf(length, sizeof(length), "running");
		}
	      else
		{
		  snprintf (logouttime, sizeof (logouttime), "still running");
		  length[0] = '\0';
		}
	      break;
	    default:
	      snprintf (logouttime, sizeof (logouttime), "ERROR");
	      snprintf(length, sizeof(length), "Unknown: %d", type);
	      break;
	    }
	}
    }

  if (type == BOOT_TIME)
    {
      tty = "system boot";
      after_reboot = 1;
    }

  char *print_service = NULL;
  if (noservice)
    print_service = strdup ("");
  else
    {
      if (asprintf (&print_service, " %-12.12s", service) < 0)
	{
	  fprintf (stderr, "Out f memory");
	  exit (EXIT_FAILURE);
	}
    }

  if (dflag && strlen (host) > 0)
    {
      struct sockaddr_storage addr;
      int addr_type = 0;

      if (isipaddr (host, &addr_type, &addr))
	{
	  if (getnameinfo ((struct sockaddr*)&addr, sizeof (addr), host_buf, sizeof (host_buf),
			   NULL, 0, NI_NAMEREQD) == 0)
	    host = host_buf;
	}
    }

  if (iflag && strlen (host) > 0)
    {
      struct addrinfo  hints;
      struct addrinfo  *result;

      memset(&hints, 0, sizeof(hints));
      hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
      hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
      hints.ai_flags = 0;
      hints.ai_protocol = 0;          /* Any protocol */
      if (getaddrinfo(host, NULL, &hints, &result) == 0)
	{
	  if (result->ai_family == AF_INET)
	    {
	      if (inet_ntop(result->ai_family,
			    &((struct sockaddr_in *)result->ai_addr)->sin_addr,
			    host_buf, sizeof (host_buf)) != NULL)
		host = host_buf;
	    }
	  else if (result->ai_family == AF_INET6)
	    {
	      if (inet_ntop(result->ai_family,
			    &((struct sockaddr_in6 *)result->ai_addr)->sin6_addr,
			    host_buf, sizeof (host_buf)) != NULL)
		host = host_buf;
	    }

	  freeaddrinfo(result);
	}
    }

  print_line (user, tty, host, print_service, logintime, logouttime, length);

  if (xflag && (type == BOOT_TIME) && newer_boot != 0 && logout_t != 0)
    {
      format_time (login_fmt, logintime, sizeof (logintime),
		   logout_t/USEC_PER_SEC);
      format_time (logout_fmt, logouttime, sizeof (logouttime),
		   newer_boot/USEC_PER_SEC);
      calc_time_length (length, sizeof(length), logout_t, newer_boot);

      print_line ("shutdown", "system down", host, print_service,
		  logintime, logouttime, length);
    }
  if (xflag && (type == BOOT_TIME))
    newer_boot = login_t;

  free (print_service);

  currentry++;

  return 0;
}

static void
usage (int retval)
{
  FILE *output = (retval != EXIT_SUCCESS) ? stderr : stdout;

  fprintf (output, "Usage: wtmpdb [command] [options]\n");
  fputs ("Commands: last, boot, boottime, rotate, shutdown, import\n\n", output);
  fputs ("Options for last:\n", output);
  fputs ("  -a, --hostlast      Display hostnames as last entry\n", output);
  fputs ("  -d, --dns           Translate IP addresses into a hostname\n", output);
  fputs ("  -f, --file FILE     Use FILE as wtmpdb database\n", output);
  fputs ("  -F, --fulltimes     Display full times and dates\n", output);
  fputs ("  -i, --ip            Translate hostnames to IP addresses\n", output);
  fputs ("  -j, --json          Generate JSON output\n", output);
  fputs ("  -n, --limit N, -N   Display only first N entries\n", output);
  fputs ("  -p, --present TIME  Display who was present at TIME\n", output);
  fputs ("  -R, --nohostname    Don't display hostname\n", output);
  fputs ("  -S, --service       Display PAM service used to login\n", output);
  fputs ("  -s, --since TIME    Display who was logged in after TIME\n", output);
  fputs ("  -t, --until TIME    Display who was logged in until TIME\n", output);
  fputs ("  -w, --fullnames     Display full IP addresses and user and domain names\n", output);
  fputs ("  -x, --system        Display system shutdown entries\n", output);
  fputs ("      --time-format FORMAT  Display timestamps in the specified FORMAT:\n", output);
  fputs ("                              notime|short|full|iso\n", output);

  fputs ("  [username...]       Display only entries matching these arguments\n", output);
  fputs ("  [tty...]            Display only entries matching these arguments\n", output);
  fputs ("TIME must be in the format \"YYYY-MM-DD HH:MM:SS\"\n", output);
  fputs ("\n", output);

  fputs ("Options for boot (writes boot entry to wtmpdb):\n", output);
  fputs ("  -f, --file FILE     Use FILE as wtmpdb database\n", output);
  fputs ("\n", output);

  fputs ("Options for boottime (print time of last system boot):\n", output);
  fputs ("  -f, --file FILE     Use FILE as wtmpdb database\n", output);
  fputs ("\n", output);

  fputs ("Options for rotate (exports old entries to wtmpdb_<datetime>)):\n", output);
  fputs ("  -f, --file FILE     Use FILE as wtmpdb database\n", output);
  fputs ("  -d, --days INTEGER  Export all entries which are older than the given days\n", output);
  fputs ("\n", output);

  fputs ("Options for shutdown (writes shutdown time to wtmpdb):\n", output);
  fputs ("  -f, --file FILE     Use FILE as wtmpdb database\n", output);
  fputs ("\n", output);

  fputs ("Options for import (imports legacy wtmp logs):\n", output);
  fputs ("  -f, --file FILE     Use FILE as wtmpdb database\n", output);
  fputs ("  logs...             Legacy log files to import\n", output);
  fputs ("\n", output);

  fputs ("Generic options:\n", output);
  fputs ("  -h, --help          Display this help message and exit\n", output);
  fputs ("  -v, --version       Print version number and exit\n", output);
  fputs ("\n", output);
  exit (retval);
}

static int
main_rotate (int argc, char **argv)
{
  struct option const longopts[] = {
    {"file", required_argument, NULL, 'f'},
    {"days", no_argument, NULL, 'd'},
    {NULL, 0, NULL, '\0'}
  };
  char *error = NULL;
  int days = LOGROTATE_DAYS;
  char *wtmpdb_backup = NULL;
  uint64_t entries = 0;

  int c;

  while ((c = getopt_long (argc, argv, "f:d:", longopts, NULL)) != -1)
    {
      switch (c)
        {
        case 'f':
          wtmpdb_path = optarg;
          break;
	case 'd':
	  days = atoi (optarg);
	  break;
        default:
          usage (EXIT_FAILURE);
          break;
        }
    }

  if (argc > optind)
    {
      fprintf (stderr, "Unexpected argument: %s\n", argv[optind]);
      usage (EXIT_FAILURE);
    }

  if (wtmpdb_rotate (wtmpdb_path, days, &error,
		     &wtmpdb_backup, &entries) != 0)
    {
      if (error)
        {
          fprintf (stderr, "%s\n", error);
          free (error);
        }
      else
        fprintf (stderr, "Couldn't read all wtmp entries\n");

      exit (EXIT_FAILURE);
    }

  if (entries == 0 || wtmpdb_backup == NULL)
    printf ("No old entries found\n");
  else
    printf ("%lli entries moved to %s\n",
	    (long long unsigned int)entries, wtmpdb_backup);

  free (wtmpdb_backup);

  return EXIT_SUCCESS;
}

static int
main_last (int argc, char **argv)
{
  struct option const longopts[] = {
    {"hostlast", no_argument, NULL, 'a'},
    {"dns", no_argument, NULL, 'd'},
    {"file", required_argument, NULL, 'f'},
    {"fullnames", no_argument, NULL, 'w'},
    {"fulltimes", no_argument, NULL, 'F'},
    {"ip", no_argument, NULL, 'i'},
    {"limit", required_argument, NULL, 'n'},
    {"present", required_argument, NULL, 'p'},
    {"nohostname", no_argument, NULL, 'R'},
    {"service", no_argument, NULL, 'S'},
    {"since", required_argument, NULL, 's'},
    {"system", no_argument, NULL, 'x'},
    {"until", required_argument, NULL, 'u'},
    {"time-format", required_argument, NULL, TIMEFMT_VALUE},
    {"json", no_argument, NULL, 'j'},
    {NULL, 0, NULL, '\0'}
  };
  int time_fmt = TIMEFMT_CTIME;
  char *error = NULL;
  int c;

  while ((c = getopt_long (argc, argv, "0123456789adf:Fijn:p:RSs:t:wx",
			   longopts, NULL)) != -1)
    {
      switch (c)
        {
	case '0':
	case '1':
	case '2':
	case '3':
	case '4':
	case '5':
	case '6':
	case '7':
	case '8':
	case '9':
	  maxentries = maxentries * 10 + c - '0';
	  break;
	case 'a':
	  hostlast = 1;
	  break;
	case 'd':
	  dflag = 1;
	  break;
        case 'f':
          wtmpdb_path = optarg;
          break;
	case 'F':
	  login_fmt = TIMEFMT_CTIME;
	  login_len = 24;
	  logout_fmt = TIMEFMT_CTIME;
	  logout_len = 24;
	  break;
	case 'i':
	  iflag = 1;
	  break;
	case 'j':
	  jflag = 1;
	  break;
	case 'n':
	  maxentries = strtoul (optarg, NULL, 10);
	  break;
	case 'p':
	  if (parse_time (optarg, &present) < 0)
	    {
	      fprintf (stderr, "Invalid time value '%s'\n", optarg);
	      exit (EXIT_FAILURE);
	    }
	  break;
	case 'R':
	  nohostname = 1;
	  break;
	case 's':
	  if (parse_time (optarg, &since) < 0)
	    {
	      fprintf (stderr, "Invalid time value '%s'\n", optarg);
	      exit (EXIT_FAILURE);
	    }
	  break;
	case 'S':
	  noservice = 0;
	  break;
	case 'u':
	  if (parse_time (optarg, &until) < 0)
	    {
	      fprintf (stderr, "Invalid time value '%s'\n", optarg);
	      exit (EXIT_FAILURE);
	    }
	  break;
	case 'w':
	  wflag = 1;
	  break;
	case 'x':
	  xflag = 1;
	  break;
	case TIMEFMT_VALUE:
	  time_fmt = time_format (optarg);
	  if (time_fmt == -1)
	    {
	      fprintf (stderr, "Invalid time format '%s'\n", optarg);
	      exit (EXIT_FAILURE);
	    }
	  break;
        default:
          usage (EXIT_FAILURE);
          break;
        }
    }

  if (argc > optind)
    match = argv + optind;

  if (nohostname && hostlast)
    {
      fprintf (stderr, "The options -a and -R cannot be used together.\n");
      usage (EXIT_FAILURE);
    }

  if (nohostname && dflag)
    {
      fprintf (stderr, "The options -d and -R cannot be used together.\n");
      usage (EXIT_FAILURE);
    }

  if (nohostname && iflag)
    {
      fprintf (stderr, "The options -i and -R cannot be used together.\n");
      usage (EXIT_FAILURE);
    }

  if (dflag && iflag)
    {
      fprintf (stderr, "The options -d and -i cannot be used together.\n");
      usage (EXIT_FAILURE);
    }

  if (jflag)
    printf ("{\n   \"entries\": [\n");

  if (wtmpdb_read_all (wtmpdb_path, print_entry, &error) != 0)
    {
      if (error)
        {
          fprintf (stderr, "%s\n", error);
          free (error);
        }
      else
        fprintf (stderr, "Couldn't read all wtmp entries\n");

      exit (EXIT_FAILURE);
    }

  if (wtmp_start == UINT64_MAX)
    {
      if (!jflag)
	printf ("%s has no entries\n", wtmpdb_path?wtmpdb_path:"wtmpdb");
    }
  else if (time_fmt != TIMEFMT_NOTIME)
    {
      char wtmptime[32];
      format_time (time_fmt, wtmptime, sizeof (wtmptime),
		   wtmp_start/USEC_PER_SEC);
      if (jflag)
	printf ("\n   ],\n   \"start\": \"%s\"\n", wtmptime);
      else
	printf ("\n%s begins %s\n", wtmpdb_path?wtmpdb_path:"wtmpdb", wtmptime);
    }
  else if (jflag)
    printf ("\n   ]\n");

  if (jflag)
    printf ("}\n");
  return EXIT_SUCCESS;
}

#if HAVE_AUDIT
static void
log_audit (int type)
{
  int audit_fd = audit_open();

  if (audit_fd < 0)
    {
      fprintf (stderr, "Failed to connect to audit daemon: %s\n",
	       strerror (errno));
      return;
    }

  if (audit_log_user_comm_message(audit_fd, type, "", "wtmpdb", NULL, NULL, NULL, 1) < 0)
    fprintf (stderr, "Failed to send audit message: %s",
	     strerror (errno));
  audit_close (audit_fd);
}
#endif

static struct timespec
diff_timespec(const struct timespec *time1, const struct timespec *time0)
{
  struct timespec diff = {.tv_sec = time1->tv_sec - time0->tv_sec,
    .tv_nsec = time1->tv_nsec - time0->tv_nsec};
  if (diff.tv_nsec < 0) {
    diff.tv_nsec += 1000000000; // nsec/sec
    diff.tv_sec--;
  }
  return diff;
}

#if HAVE_SYSTEMD
/* Find out if it was a soft-reboot. With systemd v256 we can query systemd
   for this.
   Return values:
   -1: no systemd support
   0: no soft-reboot
   >0: number of soft-reboots
*/
static int
soft_reboots_count (void)
{
  unsigned soft_reboots_count = -1;
  _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
  sd_bus_error error = SD_BUS_ERROR_NULL;
  int r;

  if (sd_bus_open_system (&bus) < 0)
    {
      fprintf (stderr, "Error: cannot open dbus");
      return -1;
    }

  r = sd_bus_get_property_trivial (bus, "org.freedesktop.systemd1",
				   "/org/freedesktop/systemd1",
				   "org.freedesktop.systemd1.Manager",
				   "SoftRebootsCount",
				   &error, 'u', &soft_reboots_count);
  if (r < 0)
    {
      /* systemd is too old, don't print error */
      if (!sd_bus_error_has_name (&error, SD_BUS_ERROR_UNKNOWN_PROPERTY))
	{
	  /* error occured, log it and return to fallback code */
	  if (error.message)
	    fprintf (stderr,
		     "Failed to get SoftRebootsCount property: %s\n",
		     error.message);
	}
      sd_bus_error_free (&error);
      return -1;
    }
  return soft_reboots_count;
}
#endif

static int
main_boot (int argc, char **argv)
{
  struct option const longopts[] = {
    {"file", required_argument, NULL, 'f'},
    {"quiet", no_argument, NULL, 'q'},
    {NULL, 0, NULL, '\0'}
  };
  char *error = NULL;
  int c;
  int soft_reboot = 0;
#if HAVE_SYSTEMD
  int quiet = 0;
#endif

  while ((c = getopt_long (argc, argv, "f:q", longopts, NULL)) != -1)
    {
      switch (c)
        {
        case 'f':
          wtmpdb_path = optarg;
          break;
	case 'q':
#if HAVE_SYSTEMD
	  quiet = 1;
#endif
	  break;
        default:
          usage (EXIT_FAILURE);
          break;
        }
    }

  if (argc > optind)
    {
      fprintf (stderr, "Unexpected argument: %s\n", argv[optind]);
      usage (EXIT_FAILURE);
    }

  struct utsname uts;
  uname(&uts);

  struct timespec ts_now;
  struct timespec ts_boot;
  clock_gettime (CLOCK_REALTIME, &ts_now);
  clock_gettime (CLOCK_BOOTTIME, &ts_boot);
  uint64_t time = wtmpdb_timespec2usec (diff_timespec(&ts_now, &ts_boot));
#if HAVE_SYSTEMD
  struct timespec ts_empty = { .tv_sec = 0, .tv_nsec = 0 };
  uint64_t now = wtmpdb_timespec2usec (diff_timespec(&ts_now, &ts_empty));

  int count = soft_reboots_count ();

  if (count > 0)
    {
      time = now;
      soft_reboot = 1;
    }
  else if ((count < 0) && ((now - time) > 300 * USEC_PER_SEC) /* 5 minutes */)
    {
      if (!quiet)
	{
	  char timebuf[32];
	  printf ("Boot time too far in the past, using current time:\n");
	  format_time (TIMEFMT_CTIME, timebuf, sizeof (timebuf),
		       time/USEC_PER_SEC);
	  printf ("Boot time: %s\n", timebuf);
	  format_time (TIMEFMT_CTIME, timebuf, sizeof (timebuf),
		       now/USEC_PER_SEC);
	  printf ("Current time: %s\n", timebuf);
	}
      time = now;
      soft_reboot = 1;
    }
#endif

#if HAVE_AUDIT
  log_audit (AUDIT_SYSTEM_BOOT);
#endif

  if (wtmpdb_login (wtmpdb_path, BOOT_TIME, soft_reboot ? "soft-reboot" : "reboot", time, "~", uts.release,
		    NULL, &error) < 0)
    {
      if (error)
        {
          fprintf (stderr, "%s\n", error);
          free (error);
        }
      else
        fprintf (stderr, "Couldn't write boot entry\n");

      exit (EXIT_FAILURE);
    }

  return EXIT_SUCCESS;
}

static int
main_boottime (int argc, char **argv)
{
  struct option const longopts[] = {
    {"file", required_argument, NULL, 'f'},
    {NULL, 0, NULL, '\0'}
  };
  char *error = NULL;
  int c;
  uint64_t boottime;

  while ((c = getopt_long (argc, argv, "f:", longopts, NULL)) != -1)
    {
      switch (c)
        {
        case 'f':
          wtmpdb_path = optarg;
          break;
        default:
          usage (EXIT_FAILURE);
          break;
        }
    }

  if (argc > optind)
    {
      fprintf (stderr, "Unexpected argument: %s\n", argv[optind]);
      usage (EXIT_FAILURE);
    }

  boottime = wtmpdb_get_boottime (wtmpdb_path, &error);
  if (error)
    {
      fprintf (stderr, "Couldn't read boot entry: %s\n", error);
      free (error);
      exit (EXIT_FAILURE);
    }

  char timebuf[32];
  format_time (TIMEFMT_CTIME, timebuf, sizeof (timebuf),
	       boottime/USEC_PER_SEC);

  printf ("system boot %s\n", timebuf);

  return EXIT_SUCCESS;
}

static int
main_shutdown (int argc, char **argv)
{
  struct option const longopts[] = {
    {"file", required_argument, NULL, 'f'},
    {NULL, 0, NULL, '\0'}
  };
  char *error = NULL;
  int c;

  while ((c = getopt_long (argc, argv, "f:", longopts, NULL)) != -1)
    {
      switch (c)
        {
        case 'f':
          wtmpdb_path = optarg;
          break;
        default:
          usage (EXIT_FAILURE);
          break;
        }
    }

  if (argc > optind)
    {
      fprintf (stderr, "Unexpected argument: %s\n", argv[optind]);
      usage (EXIT_FAILURE);
    }

#if HAVE_AUDIT
  log_audit (AUDIT_SYSTEM_SHUTDOWN);
#endif

  int64_t id = wtmpdb_get_id (wtmpdb_path, "~", &error);
  if (id < 0)
    {
      if (error)
        {
          fprintf (stderr, "%s\n", error);
          free (error);
        }
      else
        fprintf (stderr, "Couldn't get ID for reboot entry\n");

      exit (EXIT_FAILURE);
    }

  struct timespec ts;
  clock_gettime (CLOCK_REALTIME, &ts);
  uint64_t time = wtmpdb_timespec2usec (ts);

  if (wtmpdb_logout (wtmpdb_path, id, time, &error) < 0)
    {
      if (error)
        {
          fprintf (stderr, "%s\n", error);
          free (error);
        }
      else
        fprintf (stderr, "Couldn't write shutdown entry\n");

      exit (EXIT_FAILURE);
    }

  return EXIT_SUCCESS;
}

static int
main_import (int argc, char **argv)
{
  struct option const longopts[] = {
    {"file", required_argument, NULL, 'f'},
    {NULL, 0, NULL, '\0'}
  };
  int c;

  while ((c = getopt_long (argc, argv, "f:", longopts, NULL)) != -1)
    {
      switch (c)
        {
        case 'f':
          wtmpdb_path = optarg;
          break;
        default:
          usage (EXIT_FAILURE);
          break;
        }
    }

  if (argc == optind)
    {
      fprintf (stderr, "No files specified to import.\n");
      usage (EXIT_FAILURE);
    }

  for (; optind < argc; optind++)
    if (import_wtmp_file (wtmpdb_path, argv[optind]) == -1)
      return EXIT_FAILURE;

  return EXIT_SUCCESS;
}

int
main (int argc, char **argv)
{
  struct option const longopts[] = {
    {"help",     no_argument,       NULL, 'h'},
    {"version",  no_argument,       NULL, 'v'},
    {NULL, 0, NULL, '\0'}
  };
  int c;

  if (strcmp (basename(argv[0]), "last") == 0)
    return main_last (argc, argv);
  else if (argc == 1)
    usage (EXIT_SUCCESS);
  else if (strcmp (argv[1], "last") == 0)
    return main_last (--argc, ++argv);
  else if (strcmp (argv[1], "boot") == 0)
    return main_boot (--argc, ++argv);
  else if (strcmp (argv[1], "shutdown") == 0)
    return main_shutdown (--argc, ++argv);
  else if (strcmp (argv[1], "boottime") == 0)
    return main_boottime (--argc, ++argv);
  else if (strcmp (argv[1], "rotate") == 0)
    return main_rotate (--argc, ++argv);
  else if (strcmp (argv[1], "import") == 0)
    return main_import (--argc, ++argv);

  while ((c = getopt_long (argc, argv, "hv", longopts, NULL)) != -1)
    {
      switch (c)
	{
	case 'h':
	  usage (EXIT_SUCCESS);
	  break;
	case 'v':
	  printf ("wtmpdb %s\n", VERSION);
	  break;
	default:
	  usage (EXIT_FAILURE);
	  break;
	}
    }

  if (argc > optind)
    {
      fprintf (stderr, "Unexpected argument: %s\n", argv[optind]);
      usage (EXIT_FAILURE);
    }

  exit (EXIT_SUCCESS);
}
