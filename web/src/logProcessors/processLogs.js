const { HoneypotState } = require('./honeypotState');
const { initGeoip } = require('./geoip');
const { process_cowrie_logs } = require('./cowrieLogs');
const { process_ftp_logs, parseFtpEvents } = require('./ftpLogs');
const { process_db_logs, parseDbEvents } = require('./dbLogs');
const { process_api_logs, parseApiEvents } = require('./apiLogs');
const { process_dns_logs } = require('./dnsLogs');
const { process_webserver_logs } = require('./webserverLogs');

// Static metadata describing each service tab on the dashboard.
const SERVICE_META = {
  cowrie:    { key: 'cowrie',    label: 'SSH (Cowrie)', origin_label: 'IP Address' },
  ftp:       { key: 'ftp',       label: 'FTP',          origin_label: 'IP Address' },
  db:        { key: 'db',        label: 'Database',     origin_label: 'Host' },
  api:       { key: 'api',       label: 'API Server',   origin_label: 'IP Address' },
  dns:       { key: 'dns',       label: 'DNS',          origin_label: 'IP Address' },
  webserver: { key: 'webserver', label: 'Webserver',    origin_label: 'IP Address' },
};

class CombinedHoneypotState {
  constructor(states){
    this.states = states; // { cowrie, ftp, db, api, dns, webserver }
  }

  prepare_template_data(){
    const services = {};
    let all = new HoneypotState();
    for(const key of Object.keys(SERVICE_META)){
      const meta = SERVICE_META[key];
      const state = this.states[key] || new HoneypotState();
      services[key] = Object.assign({key: meta.key, label: meta.label}, state.prepare_template_data(meta.origin_label));
      all = all.merge(state);
    }
    return {
      services,
      service_order: Object.keys(SERVICE_META).map(k => SERVICE_META[k]),
      all: Object.assign({key: 'all', label: 'All Services'}, all.prepare_template_data('Origin')),
    };
  }
}

// Process every honeypot service's logs and cross-reference the ones whose
// bait spans two services (FTP leaked DB creds -> DB Connect; DB "secret
// portal" lure -> API /secret-portal hit).
async function process_logs(paths, options={}){
  await initGeoip();

  const cowrieDir = paths.cowrie || process.env.LOG_DIRECTORY || '/home/cowrie/cowrie/var/log/cowrie';
  const ftpFile = paths.ftp || process.env.FTP_LOG_FILE;
  const dbFile = paths.db || process.env.DB_LOG_FILE;
  const apiFile = paths.api || process.env.API_LOG_FILE;
  const dnsFile = paths.dns || process.env.DNS_LOG_FILE;
  const webserverFile = paths.webserver || process.env.WEBSERVER_LOG_FILE;

  const apiEvents = apiFile ? parseApiEvents(apiFile) : [];
  const dbEvents = dbFile ? parseDbEvents(dbFile) : [];

  const [cowrie, ftp, db, api, dns, webserver] = await Promise.all([
    process_cowrie_logs(cowrieDir, options),
    Promise.resolve(ftpFile ? process_ftp_logs(ftpFile, dbEvents, apiEvents) : new HoneypotState()),
    Promise.resolve(dbFile ? process_db_logs(dbFile, apiEvents) : new HoneypotState()),
    Promise.resolve(apiFile ? process_api_logs(apiFile) : new HoneypotState()),
    Promise.resolve(dnsFile ? process_dns_logs(dnsFile) : new HoneypotState()),
    Promise.resolve(webserverFile ? process_webserver_logs(webserverFile) : new HoneypotState()),
  ]);

  return new CombinedHoneypotState({cowrie, ftp, db, api, dns, webserver});
}

module.exports = { process_logs, HoneypotState, SERVICE_META };
