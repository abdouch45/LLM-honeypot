const fs = require('fs');
const { DateTime } = require('luxon');
const { HoneypotState, inc } = require('./honeypotState');
const { geoipCountry } = require('./geoip');

// The honeypot's API documentation lure (see api_server/server.py get_message())
// asks agents to call /doc?agent=<name>&key=<first president of the USA>, i.e. "washington".
// A request carrying that exact key is strong proof the caller read and acted on
// the prompt-injected instructions rather than being a generic scanner.
const EXPECTED_KEY = 'washington';

function parseApiLine(line) {
  try {
    return JSON.parse(line);
  } catch (e) {
    return null;
  }
}

// Parse api_server/logs/requests.json into a flat list of timestamped events.
// Tolerates both the "key" field (current server.py) and "access_token"
// (the field name used by the in-memory process still running from before
// a later edit) since both have been observed in the log file.
function parseApiEvents(logFile){
  const events = [];
  if(!fs.existsSync(logFile)) return events;
  const lines = fs.readFileSync(logFile, 'utf8').split(/\r?\n/);
  for(const line of lines){
    if(!line) continue;
    const entry = parseApiLine(line);
    if(!entry) continue;
    const ts = entry.timestamp ? DateTime.fromISO(entry.timestamp) : null;
    if(!ts || !ts.isValid) continue;
    events.push({
      ts,
      path: entry.path || 'unknown',
      method: entry.method || 'GET',
      agent: entry.agent || null,
      client_ip: entry.client_ip || 'unknown',
      key: entry.key != null ? entry.key : (entry.access_token != null ? entry.access_token : null),
    });
  }
  return events;
}

// Build dashboard stats for the API service tab. Self-contained: the bait
// (agent param) and the proof of compliance (correct key) both live in this
// one log file. Origins are keyed by client_ip rather than the agent name,
// since the agent param is attacker-controlled and varies per request.
function process_api_logs(logFile){
  const state = new HoneypotState();
  const events = parseApiEvents(logFile);

  for(const ev of events){
    const month = ev.ts.toFormat('yyyy-MM');
    const origin = ev.client_ip;
    const country = geoipCountry(origin);

    inc(state.attack_counts, origin);
    inc(state.monthly_total, month);
    if(country) inc(state.geolocation_data, country);

    // Potential: the requester self-identified with an agent name, or is
    // probing the agent-discovery endpoints.
    const isPotential = !!ev.agent || ev.path === '/agent' || ev.path === '/doc' || ev.path.startsWith('/secret-portal');
    if(isPotential){
      inc(state.ai_agent_attack_counts, origin);
      state.llm_hacking_agents += 1;
      inc(state.monthly_ai, month);
      if(country) inc(state.ai_agent_geolocation_data, country);
    }

    // Verified: it answered the key challenge correctly.
    const key = (ev.key || '').toString().replace(/^\$/, '').trim().toLowerCase();
    if(key === EXPECTED_KEY){
      state.verified_llm_agents += 1;
      inc(state.verified_ai_agent_counts, origin);
      inc(state.monthly_verified_ai, month);
      if(country) inc(state.verified_ai_geolocation_data, country);
    }
  }

  return state;
}

module.exports = { process_api_logs, parseApiEvents, EXPECTED_KEY };
