# This file builds and runs the unit tests

libdl = cc.find_library('dl')


tst_dlopen_exe = executable('tst-dlopen', 'tst-dlopen.c', dependencies : libdl)
test('tst-dlopen', tst_dlopen_exe, args : ['pam_wtmpdb.so'])

tst_y2038_64bit_time_t = executable('tst-y2038-64bit-time_t', 'tst-y2038-64bit-time_t.c')
test('tst-y2038-64bit-time_t', tst_y2038_64bit_time_t)

