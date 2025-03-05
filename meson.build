project(
  'wtmpdb',
  'c',
  meson_version : '>= 0.61.0',
  default_options : [
                  'prefix=/usr',
                  'sysconfdir=/etc',
                  'localstatedir=/var',
                  'buildtype=debugoptimized',
  		  'default_library=shared',
		  'b_pie=true',
                  'b_lto=true',
		  'warning_level=2'],
  license : ['BSD-2-Clause'],
  version : '0.72.0',
)

conf = configuration_data()
conf.set_quoted('VERSION', meson.project_version())
conf.set_quoted('PACKAGE', meson.project_name())

cc = meson.get_compiler('c')
pkg = import('pkgconfig')
inc = include_directories(['include','lib'])

add_project_arguments(['-D_GNU_SOURCE=1',
		       '-DXTSTRINGDEFINES',
		       '-D_FORTIFY_SOURCE=2',
                       '-D_FILE_OFFSET_BITS=64',
                       '-D_TIME_BITS=64'], language : 'c')

possible_cc_flags = [
		  '-fstack-protector-strong',
		  '-funwind-tables',
		  '-fasynchronous-unwind-tables',
		  '-fstack-clash-protection',
		  '-Werror=return-type',
		  '-Wbad-function-cast',
		  '-Wcast-align',
		  '-Wcast-qual',
                  '-Wformat-security',
		  '-Winline',
		  '-Wmissing-declarations',
		  '-Wmissing-prototypes',
		  '-Wnested-externs',
		  '-Wshadow',
		  '-Wstrict-prototypes',
		  '-Wundef',
		  ]
add_project_arguments(cc.get_supported_arguments(possible_cc_flags), language : 'c')

fs = import('fs')
if get_option('split-usr') == 'auto'
        split_usr = not fs.is_symlink('/bin')
else
        split_usr = get_option('split-usr') == 'true'
endif

rootprefixdir = get_option('rootprefix')
rootprefix_default = split_usr ? '/' : '/usr'
if rootprefixdir == ''
        rootprefixdir = rootprefix_default
endif

rootlibdir = get_option('rootlibdir')
if rootlibdir == ''
        # This will be a relative path if libdir is in prefix.
        rootlibdir = get_option('libdir')
endif
if not rootlibdir.startswith('/')
        # If we have a relative path, add rootprefixdir to the front.
        rootlibdir = rootprefixdir / rootlibdir
endif

pamlibdir = get_option('pamlibdir')
if pamlibdir == ''
        pamlibdir = rootlibdir / 'security'
endif

# Meson ignores the preceding arguments when joining paths if an absolute
# component is encountered, so this should canonicalize various paths when they
# are absolute or relative.
prefixdir = get_option('prefix')
if not prefixdir.startswith('/')
        error('Prefix is not absolute: "@0@"'.format(prefixdir))
endif
if prefixdir != rootprefixdir and rootprefixdir != '/' and not prefixdir.strip('/').startswith(rootprefixdir.strip('/') + '/')
        error('Prefix is not below root prefix (now rootprefix=@0@ prefix=@1@)'.format(rootprefixdir, prefixdir))
endif
libexecdir = join_paths(prefixdir, get_option('libexecdir'))
systemunitdir = prefixdir / 'lib/systemd/system'
tmpfilesdir = prefixdir / 'lib/tmpfiles.d'

libpam = cc.find_library('pam')
libsqlite3 = cc.find_library('sqlite3')

libaudit = dependency('audit', required : get_option('audit'))
conf.set10('HAVE_AUDIT', libaudit.found())

libsystemd = dependency('libsystemd', version: '>= 257', required : get_option('wtmpdbd'))
conf.set10('WITH_WTMPDBD', libsystemd.found())

if libsystemd.found()
          have_systemd257 = true
else
# for soft-reboot older libsystemd with sd_bus is good enough
          have_systemd257 = false
          libsystemd = dependency('libsystemd', required : get_option('systemd'))
endif
conf.set10('HAVE_SYSTEMD', libsystemd.found())

libwtmpdb_c = files('lib/libwtmpdb.c', 'lib/logwtmpdb.c', 'lib/sqlite.c', 'lib/varlink.c', 'lib/mkdir_p.c')
libwtmpdb_map = 'lib/libwtmpdb.map'
libwtmpdb_map_version = '-Wl,--version-script,@0@/@1@'.format(meson.current_source_dir(), libwtmpdb_map)

pam_wtmpdb_c = files('src/pam_wtmpdb.c')
pam_wtmpdb_map = 'src/pam_wtmpdb.map'
pam_wtmpdb_map_version = '-Wl,--version-script,@0@/@1@'.format(meson.current_source_dir(), pam_wtmpdb_map)

libwtmpdb = shared_library(
  'wtmpdb',
  libwtmpdb_c,
  include_directories : inc,
  link_args : ['-shared',
               libwtmpdb_map_version],
  link_depends : libwtmpdb_map,
  dependencies : [libsqlite3, libsystemd],
  install : true,
  version : meson.project_version(),
  soversion : '0'
)
install_headers('include/wtmpdb.h')

pkg.generate(
  libwtmpdb,
  name : 'libwtmpdb',
  description : 'library to record all logins and logouts',
  version : meson.project_version(),
)

pam_wtmpdb = shared_library(
  'pam_wtmpdb',
  pam_wtmpdb_c,
  name_prefix : '',
  include_directories : inc,
  link_args : ['-shared', pam_wtmpdb_map_version],
  link_depends : pam_wtmpdb_map,
  link_with : libwtmpdb,
  dependencies : [libpam],
  install : true,
  install_dir : pamlibdir
)

wtmpdb_c = ['src/wtmpdb.c', 'src/import.c']
wtmpdbd_c = ['src/wtmpdbd.c', 'src/varlink-org.openSUSE.wtmpdb.c', 'lib/mkdir_p.c']

if have_systemd257
  executable('wtmpdbd',
             wtmpdbd_c,
             include_directories : inc,
             link_with : libwtmpdb,
             dependencies : [libsystemd],
             install_dir : libexecdir,
             install : true)
endif

executable('wtmpdb',
           wtmpdb_c,
           include_directories : inc,
           link_with : libwtmpdb,
           dependencies : [libaudit, libsystemd],
           install : true)

if get_option('compat-symlink')
  install_symlink('last',
                  pointing_to: 'wtmpdb',
                  install_dir: 'bin')
endif

subdir('tmpfiles.d')
subdir('units')

# Unit tests
subdir('tests')

# Manual pages
subdir('man')

config_h = configure_file(
  output : 'config.h',
  configuration : conf)
