install_data('wtmpdb-update-boot.service', install_dir : systemunitdir)
install_data('wtmpdb-rotate.service', install_dir : systemunitdir)
install_data('wtmpdb-rotate.timer', install_dir : systemunitdir)

if have_systemd257
install_data('wtmpdbd.service', install_dir : systemunitdir)
install_data('wtmpdbd.socket', install_dir : systemunitdir)
endif
