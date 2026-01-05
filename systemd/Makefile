.PHONY: install uninstall

M4 = m4

INSTALL_BIN_DIR = /usr/local/sbin
INSTALL_SERVICE_DIR = /etc/systemd/system
PKG_INSTALL = false

LOGIN_SERVICE = keepassxc-login-monitor.service
SVC_FILENAMES := $(LOGIN_SERVICE) keepassxc-unlock@.service
SVC_FILES := $(patsubst %,$(BUILD_DIR)/%,$(SVC_FILENAMES))

.PHONY: all clean install uninstall

all: $(SVC_FILES)

$(BUILD_DIR)/%.service: %.service.in
	$(M4) -DINSTALL_BIN_DIR=$(INSTALL_BIN_DIR) $< > $@

clean:
	rm -f $(BUILD_DIR)/*.service

install: $(SVC_FILES)
	[ -e $(INSTALL_ROOT)/$(INSTALL_SERVICE_DIR) ] || mkdir -p $(INSTALL_ROOT)/$(INSTALL_SERVICE_DIR)
	[ "$(PKG_INSTALL)" = "true" ] || systemctl stop $(LOGIN_SERVICE) 2>/dev/null || /bin/true
	install -m 0644 $(SVC_FILES) $(INSTALL_ROOT)/$(INSTALL_SERVICE_DIR)/
	if [ "$(PKG_INSTALL)" != "true" ]; then \
		systemctl daemon-reload; \
		systemctl enable --now keepassxc-login-monitor.service; \
	fi

uninstall:
	if [ "$(PKG_INSTALL)" != "true" ]; then \
		for unit in `systemctl -q list-units 'keepassxc-unlock@*.service' | awk '{ print $$1 }'`; do \
			systemctl stop "$$unit" 2>/dev/null || /bin/true; \
		done; \
		systemctl stop $(LOGIN_SERVICE) 2>/dev/null || /bin/true; \
		systemctl disable $(LOGIN_SERVICE) || /bin/true; \
	fi
	for svc in $(SVC_FILENAMES); do \
		rm -f $(INSTALL_ROOT)/$(INSTALL_SERVICE_DIR)/$${svc}; \
	done
	[ "$(PKG_INSTALL)" = "true" ] || systemctl daemon-reload
