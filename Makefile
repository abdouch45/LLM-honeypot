# Makefile for setting up Cowrie with custom files/config and systemd service

# Python 3.10+ is required for Cowrie. We use uv to ensure the correct version
# is available regardless of the system's default Python version.
COWRIE_DIR := $(HOME)/cowrie

install:
	git clone https://github.com/cowrie/cowrie.git $(COWRIE_DIR) || true

	cd $(COWRIE_DIR) && \
		uv venv cowrie-env && \
		. cowrie-env/bin/activate && \
		uv pip install --upgrade pip setuptools wheel && \
		uv pip install -r requirements.txt && \
		uv pip install -e .

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

start:
	cd $(COWRIE_DIR) && . cowrie-env/bin/activate && \
	nohup cowrie-env/bin/python cowrie-env/bin/twistd --umask 0022 --pidfile=twistd.pid -l var/log/cowrie/cowrie.log cowrie >/dev/null 2>&1 &


stop:
	cd $(COWRIE_DIR) && kill `cat twistd.pid`


.PHONY: install start stop
