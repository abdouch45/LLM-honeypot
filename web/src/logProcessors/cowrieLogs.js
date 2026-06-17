const fs = require('fs');
const path = require('path');
const xxhash = require('xxhashjs');
const { DateTime } = require('luxon');
const { HoneypotState, inc, median } = require('./honeypotState');
const { initGeoip, geoipCountry } = require('./geoip');

// Pattern to detect LLM AI agents by their characteristic command signatures
// These are honeypot-specific commands that only AI agents would try to execute
const AI_AGENT_PATTERN = new RegExp(
  [
    'cat8193','cat8197','yellow8193','washington','george',
    'sysctl-recovery\\s+--token','server-init\\s+--key','id-service\\s+--key',
    'fsck-repair\\s+--key','disk-recover\\s+--auth'
  ].join('|'), 'i'
);

// Excluded IPs (testing/internal sources, not real attackers)
const EXCLUDED_IPS = ['149.3.60.167','213.134.160.192','80.85.142.57'];

// Main function: process all cowrie log files and extract honeypot statistics.
// Uses caching to avoid re-processing unchanged files.
async function process_cowrie_logs(logDir, options={}){
  const LOG_DIRECTORY = logDir || process.env.LOG_DIRECTORY || '/home/cowrie/cowrie/var/log/cowrie';
  const CACHE_FILE = process.env.CACHE_FILE || '/data/stats/honeypot_cache.json';
  const ARCHIVED_FILES_PATH = process.env.ARCHIVED_FILES_PATH || '/data/stats/archived_files.json';

  const stateCache = {};
  try{ if(fs.existsSync(CACHE_FILE)){ const raw = JSON.parse(fs.readFileSync(CACHE_FILE)); for(const k in raw) { const s = new HoneypotState(); Object.assign(s, raw[k]); stateCache[k]=s; } } }catch(e){/*ignore*/}

  await initGeoip();

  const files = fs.existsSync(LOG_DIRECTORY) ? fs.readdirSync(LOG_DIRECTORY).filter(f=>f.startsWith('cowrie.json')) : [];
  if(!files.length) return new HoneypotState();

  const archived = fs.existsSync(ARCHIVED_FILES_PATH) ? JSON.parse(fs.readFileSync(ARCHIVED_FILES_PATH)) : {};

  const processFile = (filePath)=>{
    const state = new HoneypotState();
    const session_commands = Object.create(null);
    try{
      const full = fs.readFileSync(filePath,'utf8');
      const lines = full.split(/\r?\n/);
      lines.forEach(line=>{
        if(!line) return;
        try{
          const log_entry = JSON.parse(line);
          const src_ip = log_entry.src_ip;
          if(src_ip && EXCLUDED_IPS.includes(src_ip)) return;
          const eventid = log_entry.eventid;
          const timestamp = log_entry.timestamp ? DateTime.fromISO(log_entry.timestamp) : null;

          if(eventid === 'cowrie.session.connect' && src_ip && timestamp){
            const month = timestamp.toFormat('yyyy-MM');
            inc(state.attack_counts, src_ip);
            inc(state.monthly_total, month);
            const country = geoipCountry(src_ip);
            if(country) inc(state.geolocation_data, country);
          }
          else if(eventid === 'cowrie.command.input' && timestamp){
            const session = log_entry.session;
            const input = log_entry.input || '';
            session_commands[session] = session_commands[session] || [];
            session_commands[session].push({ts: timestamp, input});
          }

          const input_text = log_entry.input || '';
          if(src_ip && input_text && AI_AGENT_PATTERN.test(input_text)){
            inc(state.ai_agent_attack_counts, src_ip);
            const country = geoipCountry(src_ip);
            if(country) inc(state.ai_agent_geolocation_data, country);
            const month = timestamp ? timestamp.toFormat('yyyy-MM') : 'unknown';
            state.llm_hacking_agents += 1;
            inc(state.monthly_ai, month);
          }
        }catch(e){ /* ignore line parse */ }
      });

      // Verify AI agents using command timing heuristic: real AI agents execute
      // commands much faster than humans (median < 2 seconds between commands)
      for(const sess in session_commands){
        const cmds = session_commands[sess].sort((a,b)=>a.ts - b.ts);
        if(cmds.length<=1) continue;

        const intervals = [];
        for(let i=0;i<cmds.length-1;i++) intervals.push((cmds[i+1].ts - cmds[i].ts)/1000);

        if(median(intervals) < 2.0){
          state.verified_llm_agents += 1;
          const month = cmds[0].ts.toFormat('yyyy-MM');
          inc(state.monthly_verified_ai, month);
          for(const ip in state.ai_agent_attack_counts){
            inc(state.verified_ai_agent_counts, ip);
            const c = geoipCountry(ip);
            if(c) inc(state.verified_ai_geolocation_data, c);
          }
        }
      }
    }catch(e){/* read error */}
    return state;
  };

  const states = [];
  for(const f of files){
    const full = path.join(LOG_DIRECTORY,f);
    const data = fs.readFileSync(full);
    const h = xxhash.h64().update(data).digest().toString(16);
    if(/^cowrie.json\.[0-9]+/.test(f)) archived[f]=h;
    if(stateCache[h]){ states.push(stateCache[h]); continue; }
    const s = processFile(full);
    stateCache[h]=s;
    states.push(s);
  }

  let final = new HoneypotState();
  for(const s of states) final = final.merge(s);

  try{ fs.writeFileSync(CACHE_FILE, JSON.stringify(Object.fromEntries(Object.entries(stateCache).map(([k,v])=>[k,v.toJSON()]))) ); }catch(e){}
  try{ fs.writeFileSync(ARCHIVED_FILES_PATH, JSON.stringify(archived)); }catch(e){}

  return final;
}

module.exports = { process_cowrie_logs };
