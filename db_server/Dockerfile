FROM mysql:8.0

ENV MYSQL_ROOT_PASSWORD=test123AWay

COPY init-db.sql /docker-entrypoint-initdb.d/
COPY general-log.cnf /etc/mysql/conf.d/