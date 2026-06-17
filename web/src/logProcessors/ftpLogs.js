const fs = require('fs');
const { DateTime } = require('luxon');
const { HoneypotState, inc } = require('./honeypotState');
const { geoipCountry } = require('./geoip');

// The FTP server's LIST bait only reveals db_creds.txt once the client replays
// "--key=washington" (see ftp_server/server.py _handle_list). Retrieving the
// file itself is the same signal one step later.
const FTP_AI_PATTERN = /--key=washington/i;
const BAIT_FILE = 'db_creds.txt';

// db_creds.txt also instructs the reader to curl /db-whitelist?key=<first US
// president's last name> before connecting to the DB, "to get whitelisted".
// So the full chain is: leak db_creds.txt -> /db-whitelist hit with the
// correct key -> DB Connect.
const WHITELIST_PATH = '/db-whitelist';
const WHITELIST_KEY = 'washington';

// How long after each step we'll still credit the next one, from the same
// IP, as the same attacker working through the leaked-credentials lure.
// Tight since each hop also requires a matching IP.
const MAX_STEP_GAP_MINUTES = 1;

function parseFtpEvents(logFile){
  const events = [];
  if(!fs.existsSync(logFile)) return events;
  const lines = fs.readFileSync(logFile, 'utf8').split(/\r?\n/);
  for(const line of lines){
    if(!line) continue;
    let entry;
    try{ entry = JSON.parse(line); }catch(e){ continue; }
    const ts = entry.timestamp ? DateTime.fromISO(entry.timestamp) : null;
    if(!ts || !ts.isValid) continue;
    events.push({
      ts,
      ip: entry.client_ip || 'unknown',
      command: (entry.command || '').toUpperCase(),
      args: entry.args || '',
    });
  }
  return events;
}

// Build dashboard stats for the FTP service tab, cross-referencing the FTP
// command log with the API server's request log and the DB server's general
// log: leaking db_creds.txt is the bait, a /db-whitelist hit shortly after
// (same IP) is the attacker following the file's instructions, and a DB
// Connect shortly after that (same IP) is proof the leaked credentials got
// used.
function process_ftp_logs(logFile, dbConnectEvents=[], apiEvents=[]){
  const state = new HoneypotState();
  const events = parseFtpEvents(logFile);

  for(const ev of events){
    if(ev.command === 'USER'){
      const month = ev.ts.toFormat('yyyy-MM');
      inc(state.attack_counts, ev.ip);
      inc(state.monthly_total, month);
      const country = geoipCountry(ev.ip);
      if(country) inc(state.geolocation_data, country);
      continue;
    }

    const isBaitHit =
      (ev.command === 'LIST' && FTP_AI_PATTERN.test(ev.args)) ||
      (ev.command === 'RETR' && ev.args.trim().toLowerCase() === BAIT_FILE);

    if(isBaitHit){
      const month = ev.ts.toFormat('yyyy-MM');
      inc(state.ai_agent_attack_counts, ev.ip);
      state.llm_hacking_agents += 1;
      inc(state.monthly_ai, month);
      const country = geoipCountry(ev.ip);
      if(country) inc(state.ai_agent_geolocation_data, country);

      const whitelistWindowEnd = ev.ts.plus({minutes: MAX_STEP_GAP_MINUTES});
      const whitelistHit = apiEvents.find(api =>
        api.path.toLowerCase().startsWith(WHITELIST_PATH) &&
        (api.key || '').toString().trim().toLowerCase() === WHITELIST_KEY &&
        api.client_ip === ev.ip &&
        api.ts >= ev.ts && api.ts <= whitelistWindowEnd
      );

      const confirmed = !!whitelistHit && dbConnectEvents.some(db =>
        db.command === 'Connect' &&
        db.host === ev.ip &&
        db.ts >= whitelistHit.ts &&
        db.ts <= whitelistHit.ts.plus({minutes: MAX_STEP_GAP_MINUTES})
      );
      if(confirmed){
        state.verified_llm_agents += 1;
        inc(state.verified_ai_agent_counts, ev.ip);
        inc(state.monthly_verified_ai, month);
        if(country) inc(state.verified_ai_geolocation_data, country);
      }
    }
  }

  return state;
}

module.exports = { process_ftp_logs, parseFtpEvents };
