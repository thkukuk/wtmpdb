# This file builds and runs the unit tests

libdl = cc.find_library('dl')


tst_dlopen_exe = executable('tst-dlopen', 'tst-dlopen.c', dependencies : libdl)
test('tst-dlopen', tst_dlopen_exe, args : ['pam_wtmpdb.so'])

tst_y2038_64bit_time_t = executable('tst-y2038-64bit-time_t', 'tst-y2038-64bit-time_t.c')
test('tst-y2038-64bit-time_t', tst_y2038_64bit_time_t)

tst_logwtmpdb = executable ('tst-logwtmpdb', 'tst-logwtmpdb.c',
                        include_directories : inc,
                        link_with : libwtmpdb)
test('tst-logwtmpdb', tst_logwtmpdb)

tst_login_logout = executable ('tst-login-logout', 'tst-login-logout.c', 
                        include_directories : inc,
                        link_with : libwtmpdb)
test('tst-login-logout', tst_login_logout)

tst_get_id = executable ('tst-get_id', 'tst-get_id.c',
                        include_directories : inc,
                        link_with : libwtmpdb)
test('tst-get_id', tst_get_id)

tst_varlink = executable ('tst-varlink', 'tst-varlink.c',
                        include_directories : inc,
                        link_with : libwtmpdb)
test('tst-varlink', tst_varlink)

