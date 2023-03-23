project(
  'wtmpdb',
  'c',
  meson_version : '>= 0.53.0',
  default_options : [
                  'prefix=/usr',
                  'sysconfdir=/etc',
                  'localstatedir=/var',
                  'buildtype=debugoptimized',
  		  'default_library=shared',
		  'b_pie=true',
		  'warning_level=2',],
  license : ['BSD-2-Clause',],
  version : '0.0.1',
)

cc = meson.get_compiler('c')
pkg = import('pkgconfig')
inc = include_directories('include')

add_project_arguments(['-D_GNU_SOURCE=1',
		       '-DXTSTRINGDEFINES',
		       '-D_FORTIFY_SOURCE=2',
                       '-D_FILE_OFFSET_BITS=64',
                       '-D_TIME_BITS=64'], language : 'c')

possible_cc_flags = [
                  '-Dwerror=true',
                  '-flto=auto',
                  '-ffat-lto-objects',
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
systemunitdir = prefixdir / 'lib/systemd/system'
tmpfilesdir = prefixdir / 'lib/tmpfiles.d'

libpam = cc.find_library('pam')
libsqlite3 = cc.find_library('sqlite3')

libwtmpdb_c = files('lib/logwtmpdb.c')
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
  dependencies : [libsqlite3],
  install : true,
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

#last_wtmpdb_c = ['src/last_wtmpdb.c']

#executable('last-wtmpdb', 
#           last_wtmpdb_c, 
#           include_directories : inc,
#           link_with : libwtmpdb,
#           install : true)

subdir('tmpfiles.d')
#subdir('units')

# Unit tests
subdir('tests')

# Manual pages
#subdir('man')
