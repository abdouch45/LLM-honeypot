const fs = require('fs');
const { DateTime } = require('luxon');
const { HoneypotState, inc } = require('./honeypotState');
const { geoipCountry } = require('./geoip');

// init-db.sql seeds a "projects" row that instructs whoever reads it to POST
// to <ip>:8004/secret-portal?key=washington. Any Query that touches the
// "projects" table means the session reached that bait.
const DB_RECON_PATTERN = /\bprojects\b/i;

// How long after a DB recon hit we'll still credit a matching /secret-portal
// API request, from the same IP, as the confirmation of the same attacker
// following the lure.
const MAX_STEP_GAP_MINUTES = 1;

// MySQL general_log lines look like:
//   2026-06-16T15:26:59.838100Z\t    8 Connect\tdb_admin@localhost on  using Socket
//   2026-06-16T15:27:22.849681Z\t    8 Query\tselect * from corporate.projects
// timestamp <TAB> "<threadid> <Command>" <TAB> <argument>
function parseDbEvents(logFile){
  const events = [];
  if(!fs.existsSync(logFile)) return events;
  const lines = fs.readFileSync(logFile, 'utf8').split(/\r?\n/);
  const sessionHost = Object.create(null); // threadId -> host

  const raw = [];
  for(const line of lines){
    if(!line) continue; // skip blank lines

    const parts = line.split('\t');
    // real log lines look like: <timestamp> TAB <id Command> TAB <argument>
    // anything else (banner text, multi-line query continuations) has no tab
    if(parts.length < 2) continue;

    const ts = DateTime.fromISO(parts[0]);
    // first field must parse as an ISO timestamp, otherwise it's not a new event
    if(!ts.isValid) continue;

    // parts[1] is "<threadid> <Command>", e.g. "   8 Connect" or "  10 Query"
    const head = parts[1].trim().split(/\s+/);
    const threadId = head[0];
    const command = head.slice(1).join(' ');
    const arg = (parts[2] || '').trim(); // the query text / connect string, if any
    raw.push({ts, threadId, command, arg});

    if(command === 'Connect'){
      // Connect lines look like "<user>@<host> on <db> using <method>"
      // capture the host so later Query lines from the same threadId
      // (which don't repeat the host) can be attributed to it
      const m = arg.match(/^[^@]+@(\S+)\s+on\b/i);
      if(m) sessionHost[threadId] = m[1];
    }
  }

  for(const ev of raw){
    events.push(Object.assign({host: sessionHost[ev.threadId] || 'unknown'}, ev));
  }
  return events;
}

function hostCountry(host){
  if(host === 'localhost' || host === 'unknown') return 'Private IP';
  return geoipCountry(host);
}

// Build dashboard stats for the DB service tab, cross-referencing the
// MySQL general log with the API server's request log: a "Query" that reads
// the projects table is the bait being read, a "/secret-portal" hit with the
// correct key, from the same IP, within a minute is proof the attacker acted
// on it.
function process_db_logs(logFile, apiEvents=[]){
  const state = new HoneypotState();
  const events = parseDbEvents(logFile);

  for(const ev of events){
    if(ev.command === 'Connect'){
      const month = ev.ts.toFormat('yyyy-MM');
      inc(state.attack_counts, ev.host);
      inc(state.monthly_total, month);
      const country = hostCountry(ev.host);
      if(country) inc(state.geolocation_data, country);
      continue;
    }

    if(ev.command === 'Query' && DB_RECON_PATTERN.test(ev.arg)){
      const month = ev.ts.toFormat('yyyy-MM');
      inc(state.ai_agent_attack_counts, ev.host);
      state.llm_hacking_agents += 1;
      inc(state.monthly_ai, month);
      const country = hostCountry(ev.host);
      if(country) inc(state.ai_agent_geolocation_data, country);

      const windowEnd = ev.ts.plus({minutes: MAX_STEP_GAP_MINUTES});
      const confirmed = apiEvents.some(api =>
        api.path.toLowerCase().startsWith('/secret-portal') &&
        (api.key || '').toString().trim().toLowerCase() === 'washington' &&
        api.client_ip === ev.host &&
        api.ts >= ev.ts && api.ts <= windowEnd
      );
      if(confirmed){
        state.verified_llm_agents += 1;
        inc(state.verified_ai_agent_counts, ev.host);
        inc(state.monthly_verified_ai, month);
        if(country) inc(state.verified_ai_geolocation_data, country);
      }
    }
  }

  return state;
}

module.exports = { process_db_logs, parseDbEvents };
