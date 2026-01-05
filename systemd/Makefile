.PHONY: install uninstall

M4 = m4

LOGIN_SERVICE = keepassxc-login-monitor.service
SERVICES := $(LOGIN_SERVICE) keepassxc-unlock@.service

install:
	[ $(PKG_INSTALL) = "true" ] || systemctl stop $(LOGIN_SERVICE) 2>/dev/null || /bin/true
	$(M4) -DINSTALL_BIN_DIR=$(INSTALL_BIN_DIR) keepassxc-login-monitor.service.in > $(BUILD_DIR)/keepassxc-login-monitor.service
	$(M4) -DINSTALL_BIN_DIR=$(INSTALL_BIN_DIR) keepassxc-unlock@.service.in > $(BUILD_DIR)/keepassxc-unlock@.service
	install -m 0644 $(BUILD_DIR)/*.service $(INSTALL_ROOT)/$(INSTALL_SERVICE_DIR)
	[ $(PKG_INSTALL) = "true" ] || systemctl daemon-reload
	[ $(PKG_INSTALL) = "true" ] || systemctl enable --now keepassxc-login-monitor.service

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
