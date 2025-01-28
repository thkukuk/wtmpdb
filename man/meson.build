xsltproc_exe = find_program('xsltproc', required : get_option('man'))
want_man = (get_option('man').enabled() or get_option('man').auto()) and xsltproc_exe.found()
xsltproc_flags = [
        '--nonet',
        '--xinclude',
        '--stringparam', 'version', '@0@'.format(meson.project_version()),
        '--path',
        '@0@:@1@'.format(meson.current_build_dir(), meson.current_source_dir())]

custom_man_xsl = files('custom-man.xsl')

xslt_cmd = [xsltproc_exe, '-o', '@OUTPUT0@'] + xsltproc_flags

mandir8 = get_option('mandir') /'man8'

if xsltproc_exe.found()
custom_target('pam_wtmpdb.8',
              input : 'pam_wtmpdb.8.xml',
              output : 'pam_wtmpdb.8',
              command : xslt_cmd + [custom_man_xsl, '@INPUT@'],
              install : want_man,
              install_dir : mandir8)
custom_target('wtmpdb.8',
              input : 'wtmpdb.8.xml',
              output : 'wtmpdb.8',
              command : xslt_cmd + [custom_man_xsl, '@INPUT@'],
              install : want_man,
              install_dir : mandir8)
custom_target('wtmpdbd.8',
              input : 'wtmpdbd.8.xml',
              output : ['wtmpdbd.8', 'wtmpdbd.service.8', 'wtmpdbd.socket.8'],
              command : xslt_cmd + [custom_man_xsl, '@INPUT@'],
              install : want_man,
              install_dir : mandir8)
endif
