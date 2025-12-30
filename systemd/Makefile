.PHONY: install uninstall

M4 = m4

LOGIN_SERVICE = keepassxc-login-monitor.service
SERVICES := $(LOGIN_SERVICE) keepassxc-unlock@.service

install:
	$(M4) -DKEEPASSXC_LOGIN_MONITOR_BIN=$(INSTALL_BIN_DIR)/keepassxc-login-monitor keepassxc-login-monitor.service.in > $(BUILD_DIR)/keepassxc-login-monitor.service
	$(M4) -DKEEPASSXC_UNLOCK_BIN=$(INSTALL_BIN_DIR)/keepassxc-unlock keepassxc-unlock@.service.in > $(BUILD_DIR)/keepassxc-unlock@.service
	install -m 0644 $(BUILD_DIR)/*.service $(INSTALL_ROOT)/$(INSTALL_SERVICE_DIR)

uninstall:
	for unit in `systemctl -q list-units 'keepassxc-unlock@*.service' | awk '{ print $$1 }'`; do \
		systemctl stop "$$unit" 2>/dev/null || /bin/true; \
	done
	systemctl stop $(LOGIN_SERVICE) 2>/dev/null || /bin/true
	systemctl disable $(LOGIN_SERVICE) || /bin/true
	for service in $(SERVICES); do \
		rm -f /etc/systemd/system/$${service}; \
	done
	systemctl daemon-reload
