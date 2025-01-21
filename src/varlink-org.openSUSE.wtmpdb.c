//SPDX-License-Identifier: GPL-2.0-or-later

#include "varlink-org.openSUSE.wtmpdb.h"

static SD_VARLINK_DEFINE_STRUCT_TYPE(WtmpdbEntry,
				     SD_VARLINK_DEFINE_FIELD(ID,         SD_VARLINK_INT,    0),
				     SD_VARLINK_DEFINE_FIELD(Type,       SD_VARLINK_INT,    0),
				     SD_VARLINK_DEFINE_FIELD(User,       SD_VARLINK_STRING, 0),
				     SD_VARLINK_DEFINE_FIELD(Login,      SD_VARLINK_INT,    SD_VARLINK_NULLABLE),
				     SD_VARLINK_DEFINE_FIELD(Logout,     SD_VARLINK_INT,    SD_VARLINK_NULLABLE),
				     SD_VARLINK_DEFINE_FIELD(TTY,        SD_VARLINK_STRING, 0),
				     SD_VARLINK_DEFINE_FIELD(RemoteHost, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
				     SD_VARLINK_DEFINE_FIELD(Service,    SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
		Login,
		SD_VARLINK_FIELD_COMMENT("Request to add a login record"),
		SD_VARLINK_DEFINE_INPUT(Type, SD_VARLINK_INT,  0),
		SD_VARLINK_DEFINE_INPUT(User, SD_VARLINK_STRING,  0),
		SD_VARLINK_DEFINE_INPUT(LoginTime, SD_VARLINK_INT,  0),
		SD_VARLINK_DEFINE_INPUT(TTY, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
		SD_VARLINK_DEFINE_INPUT(RemoteHost, SD_VARLINK_STRING,  SD_VARLINK_NULLABLE),
		SD_VARLINK_DEFINE_INPUT(Service, SD_VARLINK_STRING,  SD_VARLINK_NULLABLE),
		SD_VARLINK_DEFINE_OUTPUT(ID, SD_VARLINK_INT, 0),
		SD_VARLINK_DEFINE_OUTPUT(ErrorMsg, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
		Logout,
		SD_VARLINK_FIELD_COMMENT("Request to close a login record with logout time"),
		SD_VARLINK_DEFINE_INPUT(ID, SD_VARLINK_INT,  0),
		SD_VARLINK_DEFINE_INPUT(LogoutTime, SD_VARLINK_INT,  0),
		SD_VARLINK_DEFINE_OUTPUT(Success, SD_VARLINK_BOOL, 0),
		SD_VARLINK_DEFINE_OUTPUT(ErrorMsg, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
		GetID,
		SD_VARLINK_FIELD_COMMENT("Get ID for active entry on TTY"),
		SD_VARLINK_DEFINE_INPUT(TTY, SD_VARLINK_STRING,  0),
		SD_VARLINK_DEFINE_OUTPUT(ID, SD_VARLINK_INT, 0),
		SD_VARLINK_DEFINE_OUTPUT(ErrorMsg, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                GetBootTime,
                SD_VARLINK_FIELD_COMMENT("Get time of last boot"),
		SD_VARLINK_DEFINE_OUTPUT(Success,  SD_VARLINK_BOOL, 0),
                SD_VARLINK_DEFINE_OUTPUT(BootTime, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT(ErrorMsg, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                ReadAll,
                SD_VARLINK_FIELD_COMMENT("Get all entries from the database"),
		SD_VARLINK_DEFINE_OUTPUT(Success,  SD_VARLINK_BOOL, 0),
		SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(Data, WtmpdbEntry, SD_VARLINK_ARRAY | SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT(ErrorMsg, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
		Rotate,
		SD_VARLINK_FIELD_COMMENT("Request to rotate database"),
		SD_VARLINK_DEFINE_INPUT(Days,        SD_VARLINK_INT,  0),
		SD_VARLINK_DEFINE_OUTPUT(Success,    SD_VARLINK_BOOL, 0),
		SD_VARLINK_DEFINE_OUTPUT(Entries,    SD_VARLINK_INT, SD_VARLINK_NULLABLE),
		SD_VARLINK_DEFINE_OUTPUT(BackupName, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
		SD_VARLINK_DEFINE_OUTPUT(ErrorMsg,   SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
		Quit,
		SD_VARLINK_FIELD_COMMENT("Stop the daemon"),
		SD_VARLINK_DEFINE_INPUT(ExitCode, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
		SD_VARLINK_DEFINE_OUTPUT(Success, SD_VARLINK_BOOL, 0));

static SD_VARLINK_DEFINE_METHOD(
		Ping,
		SD_VARLINK_FIELD_COMMENT("Check if service is alive"),
		SD_VARLINK_DEFINE_OUTPUT(Alive, SD_VARLINK_BOOL, 0));

static SD_VARLINK_DEFINE_METHOD(
                SetLogLevel,
                SD_VARLINK_FIELD_COMMENT("The maximum log level, using BSD syslog log level integers."),
                SD_VARLINK_DEFINE_INPUT(Level, SD_VARLINK_INT, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                GetEnvironment,
                SD_VARLINK_FIELD_COMMENT("Returns the current environment block, i.e. the contents of environ[]."),
                SD_VARLINK_DEFINE_OUTPUT(Environment, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY));

static SD_VARLINK_DEFINE_ERROR(NoEntryFound);
static SD_VARLINK_DEFINE_ERROR(InternalError);

SD_VARLINK_DEFINE_INTERFACE(
                org_openSUSE_wtmpdb,
                "org.openSUSE.wtmpdb",
		SD_VARLINK_INTERFACE_COMMENT("Wtmpdbd control APIs"),
		SD_VARLINK_SYMBOL_COMMENT("Add login entry"),
                &vl_method_Login,
		SD_VARLINK_SYMBOL_COMMENT("Close login entry with logout time"),
                &vl_method_Logout,
		SD_VARLINK_SYMBOL_COMMENT("Get ID for open login entry on TTY"),
                &vl_method_GetID,
		SD_VARLINK_SYMBOL_COMMENT("Get last boot time"),
                &vl_method_GetBootTime,
		SD_VARLINK_SYMBOL_COMMENT("Get all entries from database"),
                &vl_method_ReadAll,
 		SD_VARLINK_SYMBOL_COMMENT("Stop the daemon"),
                &vl_method_Quit,
		SD_VARLINK_SYMBOL_COMMENT("Checks if the service is running."),
                &vl_method_Ping,
                SD_VARLINK_SYMBOL_COMMENT("Sets the maximum log level."),
                &vl_method_SetLogLevel,
                SD_VARLINK_SYMBOL_COMMENT("Get current environment block."),
                &vl_method_GetEnvironment,
		SD_VARLINK_SYMBOL_COMMENT("No entry found"),
                &vl_error_NoEntryFound,
		SD_VARLINK_SYMBOL_COMMENT("Internal Error"),
		&vl_error_InternalError);
