# Makefile for setting up Cowrie with custom files/config and systemd service

# Python 3.10+ is required for Cowrie. We use uv to ensure the correct version
# is available regardless of the system's default Python version.
COWRIE_DIR := $(HOME)/cowrie
ROOT := $(CURDIR)
API_DIR := $(ROOT)/api_server
FTP_DIR := $(ROOT)/ftp_server
DNS_DIR := $(ROOT)/dns_honeypot
DB_LOG_DIR := $(HOME)/db-server-logs
VENV_DIR := $(ROOT)/.venv

install:
	curl -LsSf https://astral.sh/uv/install.sh | sh
	source ~/.bashrc
	git clone https://github.com/cowrie/cowrie.git $(COWRIE_DIR) || true
	cd $(COWRIE_DIR) && \
		uv venv cowrie-env && \
		. cowrie-env/bin/activate && \
		uv pip install --upgrade pip setuptools wheel && \
		uv pip install -r requirements.txt && \
		uv pip install -e .
	mkdir -p COWRIE_DIR//honeyfs/etc
	mkdir -p COWRIE_DIR//honeyfs/proc
	cp ./configs/cowrie.cfg $(COWRIE_DIR)/etc/cowrie.cfg
	cp ./configs/motd $(COWRIE_DIR)/honeyfs/etc/motd
	cp ./configs/version $(COWRIE_DIR)/honeyfs/proc/version
	cp ./configs/passwd $(COWRIE_DIR)/honeyfs/etc/passwd

	cp ./configs/cat8193.py $(COWRIE_DIR)/src/cowrie/commands/cat8193.py
	cp ./configs/init.py $(COWRIE_DIR)/src/cowrie/commands/__init__.py

	cp ./configs/df.py $(COWRIE_DIR)/src/cowrie/commands/df.py
	cp ./configs/ps.py $(COWRIE_DIR)/src/cowrie/commands/ps.py
	cp ./configs/pwd_cmd.py $(COWRIE_DIR)/src/cowrie/commands/pwd_cmd.py
	cp ./configs/whoami.py $(COWRIE_DIR)/src/cowrie/commands/whoami.py
	cp ./configs/ls.py $(COWRIE_DIR)/src/cowrie/commands/ls.py
	cp ./configs/llm_prompts.py $(COWRIE_DIR)/src/cowrie/commands/llm_prompts.py

	cp ./configs/sysctl_recovery.py $(COWRIE_DIR)/src/cowrie/commands/sysctl_recovery.py
	cp ./configs/server_init.py $(COWRIE_DIR)/src/cowrie/commands/server_init.py
	cp ./configs/id_service.py $(COWRIE_DIR)/src/cowrie/commands/id_service.py
	cp ./configs/fsck_repair.py $(COWRIE_DIR)/src/cowrie/commands/fsck_repair.py
	cp ./configs/disk_recover.py $(COWRIE_DIR)/src/cowrie/commands/disk_recover.py

	uv venv $(VENV_DIR) && \
		. $(VENV_DIR)/bin/activate && \
		uv pip install uvicorn twisted

start:
	$(MAKE) start-cowrie
	$(MAKE) start-api
	$(MAKE) start-ftp
	$(MAKE) start-dns

stop:
	$(MAKE) stop-dns
	$(MAKE) stop-ftp
	$(MAKE) stop-api
	$(MAKE) stop-cowrie

start-cowrie:
	cd $(COWRIE_DIR) && . cowrie-env/bin/activate && \
	nohup cowrie-env/bin/python cowrie-env/bin/twistd --umask 0022 --pidfile=twistd.pid -l var/log/cowrie/cowrie.log cowrie >/dev/null 2>&1 &

stop-cowrie:
	cd $(COWRIE_DIR) && kill `cat twistd.pid` || true

start-api:
	cd $(API_DIR) && . $(VENV_DIR)/bin/activate && \
	nohup uvicorn server:app --host 0.0.0.0 --port 8004 >/dev/null 2>&1 &

stop-api:
	pkill -x -f "uvicorn server:app --host 0.0.0.0 --port 8004" || true

start-ftp:
	cd $(FTP_DIR) && . $(VENV_DIR)/bin/activate && \
	nohup python3 server.py >/dev/null 2>&1 &

stop-ftp:
	pkill -x -f "python3 server.py" || true

start-dns:
	cd $(DNS_DIR) && . $(VENV_DIR)/bin/activate && \
	nohup python3 dns_honeypot.py >/dev/null 2>&1 &

stop-dns:
	pkill -x -f "python3 dns_honeypot.py" || true

docker-up:
	docker compose up --build -d

clear-db-logs:
	@if [ -f "$(DB_LOG_DIR)/general.log" ]; then \
		echo "Clearing $(DB_LOG_DIR)/general.log"; \
		truncate -s 0 "$(DB_LOG_DIR)/general.log" || true; \
	else \
		echo "$(DB_LOG_DIR)/general.log does not exist"; \
		touch "$(DB_LOG_DIR)/general.log" || true; \
	fi


.PHONY: install start stop

.PHONY: docker-up clear-db-logs
