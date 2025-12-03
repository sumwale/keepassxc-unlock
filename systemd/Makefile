.PHONY: install uninstall

LOGIN_SERVICE = keepassxc-login-monitor.service
SERVICES := $(LOGIN_SERVICE) keepassxc-unlock@.service

install:
	systemctl stop $(LOGIN_SERVICE) 2>/dev/null || /bin/true
	install -m 0644 $(SERVICES) /etc/systemd/system/
	systemctl daemon-reload
	systemctl enable --now $(LOGIN_SERVICE)

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
