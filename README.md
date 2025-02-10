# wtmpdb

**Y2038 safe version of wtmp**

## Background

`last` reports the login and logout times of users and when the machine got rebooted.

The standard `/var/log/wtmp` implementation using `utmp.h` from glibc uses a **32bit** **time_t** in `struct utmp` on bi-arch systems like x86-64 (so which can execute 64bit and 32bit binaries). So even if you have a pure 64bit system, on many architectures using glibc you have a Y2038 problem.

For background on the Y2038 problem (32bit time_t counter will overflow) I suggest to start with the wikipedia [Year 2038 problem](https://en.wikipedia.org/wiki/Year_2038_problem) article.

There is also a more [technical document](https://github.com/thkukuk/utmpx/blob/main/Y2038.md), describing the problem in more detail, which also contains a list of affected packages. And a more highlevel blog "[Y2038, glibc and wtmp on 64bit architectures](https://www.thkukuk.de/blog/Y2038_glibc_wtmp_64bit/)"

## Functionality

The main features of `wtmpdb` are:

* It's using sqlite3 as database backend.
* Data is mainly collected via a PAM module, so that every tool can make use of it, without modifying existing packages. For cases where this is not possible, there is a library `libwtmpdb`.
* The `wtmpdb last` output is as compatible as possible with the old `last` implementation, but not all options are yet supported. For compatibility reasons, a symlink `last` pointing to `wtmpdb` can be created.
* There is an optional `wtmpdbd` daemon for central management of the sqlite3 database using sd-varlink for communication with `libwtmpdb`.

**IMPORTANT** To be Y2038 safe on 32bit architectures, the binaries needs to be build with a **64bit time_t**. This should be the standard on 64bit architectures.

The package constists of a library, PAM module, a commandline interface and an optional daemon:

* `libwtmpdb.so.0` contains all high level functions to manage the data.
* `pam_wtmpdb.so` stores the login and logout time of an user into the database.
* `wtmpdb` is used to add reboot and shutdown entries and to display existing entries (like `last`).
* `wtmpdbd` is used to manage the database in a secure way.

By default the database will be written as `/var/lib/wtmpdb/wtmp.db`.

## Configuration

The `pam_wtmpdb.so` module will be added in the `session` section of the service, which should create wtmp entries.
On openSUSE Tumbleweed and MicroOS, the following line needs be added to `/etc/pam.d/postlogin-session`:

```
session optional pam_wtmpdb.so
```

This line will create a new entry in the database for every user if an application calls the PAM framework.

### OpenSSH

OpenSSH does not provide the TTY to PAM modules, but the TTY value is important to identify the correct entry. For this reasons, an openssh version with wtmpdb is required (should be openssh >= 10.0) or the wtmpdb support needs to be backported.

The PAM module (`pam_wtmpdb.so`) needs to be removed for the sshd service, or if it is configured in a "common" section, disabled:

```
session    optional        pam_wtmpdb.so   skip_if=sshd
```

## Design

### Database

sqlite3 is used for the database. The table `wtmp` contains the following columns:

* `ID` is the primary identifier for an entry and will be automatically assigned by sqlite.
* `Type` defines which kind of entry this is. Currently supported are:
  * `BOOT_TIME` is the time of system boot and shutdown
  * `RUNLEVEL` is for non-systemd systems
  * `USER_PROCESS` contains the normal user login and logout data
* `User` is a mandatory field containing the login name or "reboot" for boot/shutdown entries
* `Login` is the login time of the user in microseconds since 1.1.1970.
* `Logout` is the logout time of the user in microseconds since 1.1.1970.
* `TTY` is the tty or "~" for the "reboot" entry. If this entry got created via the PAM module, this could also contain some generic strings like `ssh` for applications, which fake the PAM_TTY entry.
* `RemoteHost` is the remote hostname from which the user did connect or the content of the display variable.
* `Service` is the PAM service which created the entry.

### API

The `libwtmpdb` library provides the following main functions beside some helper functions:

* `logwtmpdb()` is very similar to `logwtmp.3` to make it easier to convert applications.
* `wtmpdb_login()` is the function to create a new login entry.
* `wtmpdb_logout()` is the function to add the logout time to an existing entry.
* `wtmpdb_read_all()` iterates over all entries and calls a callback function with every single entry.

### Command line tool

The `wtmpdb` command supports the following tasks:

* `wtmpdb last` is a replacement for `last`.
* `wtmpdb boot` creates a boot entry.
* `wtmpdb shutdown` add the shutdown time to the current boot entry.

### Daemon

The `wtmpdbd` daemon provides a varlink interface for `libwtmpdb`. This allows to secure the database so that only root has access to it. The daemon will be started about two systemd socket units.

### systemd service

* `wtmpdb-update-boot.service` will record the boot and shutdown times of a service.
* `wtmpdbd-reader.socket` and `wtmpdbd-writer.socket` will start `wtmpdbd` on demand.
