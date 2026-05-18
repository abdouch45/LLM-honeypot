const fs = require('fs');
const path = require('path');
const xxhash = require('xxhashjs');
// maxmind is optional; require at runtime if available for geolocation
let maxmind;
let geoipInitDone = false;
let geoipAvailable = false;
let geoLookup = null;
const { DateTime } = require('luxon');

// Pattern used to recognize private IP addresses and local hosts
const PRIVATE_IP_PATTERN = /^(?:127\.0\.0\.1|10\.(?:\d{1,3}\.){2}\d{1,3}|192\.168\.(?:\d{1,3}\.)\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.(?:\d{1,3}\.)\d{1,3}|::1|fc00:|fe80:)/i;
function isPrivateIp(ip){ return PRIVATE_IP_PATTERN.test(ip); }

// Pattern to detect LLM AI agents by their characteristic command signatures
// These are honeypot-specific commands that only AI agents would try to execute
const AI_AGENT_PATTERN = new RegExp(
  [
    'cat8193','cat8197','yellow8193','washington','george',
    'sysctl-recovery\\s+--token','server-init\\s+--key','id-service\\s+--key',
    'fsck-repair\\s+--key','disk-recover\\s+--auth'
  ].join('|'), 'i'
);

// Utility: create a map object for counting occurrences
function counter() { return Object.create(null); }
// Utility: increment a counter in a map (default increment by 1)
function inc(map, key, n=1){ map[key] = (map[key]||0)+n }

// Tracks all honeypot statistics: total attacks, AI agent detections, geolocation, and monthly trends
class HoneypotState {
  constructor(){
    // General attack statistics
    this.attack_counts = counter();           // IP -> attack count
    this.geolocation_data = counter();        // Country -> attack count

    // AI agent detection statistics
    this.llm_hacking_agents = 0;              // Total suspected LLM agents
    this.verified_llm_agents = 0;             // Verified LLM agents (by command timing)
    this.ai_agent_attack_counts = counter();  // IP -> AI agent attack count
    this.verified_ai_agent_counts = counter();// IP -> verified AI agent count
    this.ai_agent_geolocation_data = counter();      // Country -> AI agent attacks
    this.verified_ai_geolocation_data = counter();   // Country -> verified AI agents

    // Monthly aggregation for trending
    this.monthly_total = counter();           // YYYY-MM -> total attacks
    this.monthly_ai = counter();              // YYYY-MM -> suspected AI attacks
    this.monthly_verified_ai = counter();     // YYYY-MM -> verified AI attacks
  }

  // Merge two HoneypotState objects by summing all counters
  merge(other){
    const res = new HoneypotState();
    res.llm_hacking_agents = this.llm_hacking_agents + other.llm_hacking_agents;
    res.verified_llm_agents = this.verified_llm_agents + other.verified_llm_agents;
    // Sum all counter maps
    for(const attr of ['attack_counts','geolocation_data','ai_agent_attack_counts','verified_ai_agent_counts','ai_agent_geolocation_data','verified_ai_geolocation_data','monthly_total','monthly_ai','monthly_verified_ai']){
      res[attr] = Object.assign({}, this[attr]);
      for(const k in other[attr]) res[attr][k] = (res[attr][k]||0)+other[attr][k];
    }
    return res;
  }

  toJSON(){
    const data = {
      llm_hacking_agents: this.llm_hacking_agents,
      verified_llm_agents: this.verified_llm_agents
    };
    for(const attr of ['attack_counts','geolocation_data','ai_agent_attack_counts','verified_ai_agent_counts','ai_agent_geolocation_data','verified_ai_geolocation_data','monthly_total','monthly_ai','monthly_verified_ai']){
      data[attr] = this[attr];
    }
    return data;
  }

  // Prepare data for rendering in HTML templates (aggregations, top lists, percentages)
  prepare_template_data(){
    // Calculate total attacks from geolocation data
    const total_attacks = Object.values(this.geolocation_data).reduce((a,b)=>a+b,0);
    // Get sorted list of months with activity
    const month_labels = Object.keys(this.monthly_total).sort();
    const monthly_attacks = month_labels.map(m=> this.monthly_total[m]||0);
    const monthly_ai_attacks = month_labels.map(m=> this.monthly_ai[m]||0);
    const monthly_verified_ai_attacks = month_labels.map(m=> this.monthly_verified_ai[m]||0);

    // Get top 10 most active IPs in each category
    const top_attackers = Object.entries(this.attack_counts).sort((a,b)=>b[1]-a[1]).slice(0,10);
    const top_ai_agents = Object.entries(this.ai_agent_attack_counts).sort((a,b)=>b[1]-a[1]).slice(0,10);
    const top_verified_ai_agents = Object.entries(this.verified_ai_agent_counts).sort((a,b)=>b[1]-a[1]).slice(0,10);

    // Calculate percentage of attacks by country for top 10 countries
    const geolocation_percentages = [];
    if(total_attacks>0){
      Object.entries(this.geolocation_data).sort((a,b)=>b[1]-a[1]).slice(0,10).forEach(([country,count])=>{
        geolocation_percentages.push([country, Math.round((count/total_attacks)*10000)/100]);
      });
    }

    // Calculate percentage of AI attacks by country
    const ai_geolocation_percentages = [];
    if(this.llm_hacking_agents>0){
      Object.entries(this.ai_agent_geolocation_data).sort((a,b)=>b[1]-a[1]).slice(0,10).forEach(([country,count])=>{
        ai_geolocation_percentages.push([country, Math.round((count/this.llm_hacking_agents)*10000)/100]);
      });
    }

    // Calculate percentage of verified AI attacks by country
    const verified_ai_geolocation_percentages = [];
    if(this.verified_llm_agents>0){
      Object.entries(this.verified_ai_geolocation_data).sort((a,b)=>b[1]-a[1]).slice(0,10).forEach(([country,count])=>{
        verified_ai_geolocation_percentages.push([country, Math.round((count/this.verified_llm_agents)*10000)/100]);
      });
    }

    // Check if latest month is the current month (and thus incomplete)
    const current_month = DateTime.now().toFormat('yyyy-MM');
    const last_month_incomplete = month_labels.length && month_labels[month_labels.length-1] === current_month;

    return {
      total_attacks,
      llm_hacking_agents: this.llm_hacking_agents,
      verified_llm_agents: this.verified_llm_agents,
      top_attackers,
      geolocation_data: geolocation_percentages,
      top_ai_agents,
      top_verified_ai_agents,
      ai_geolocation_data: ai_geolocation_percentages,
      verified_ai_geolocation_data: verified_ai_geolocation_percentages,
      month_labels,
      monthly_attacks,
      monthly_ai_attacks,
      monthly_verified_ai_attacks,
      last_month_incomplete
    };
  }
}

// Calculate the median value of an array (used for detecting AI agents by command timing)
function median(arr){
  if(!arr.length) return 0;
  const s = arr.slice().sort((a,b)=>a-b);
  const mid = Math.floor(s.length/2);
  return s.length%2 ? s[mid] : (s[mid-1]+s[mid])/2;
}

// Main function: process all log files and extract honeypot statistics
// Uses caching to avoid re-processing unchanged files
async function process_logs(logDir, options={}){
  // Configuration paths
  const LOG_DIRECTORY = logDir || process.env.LOG_DIRECTORY || '/home/cowrie/cowrie/var/log/cowrie';
  const GEOIP_DB_PATH = process.env.GEOIP_DB_PATH || path.join(process.cwd(),'GeoLite2-Country.mmdb');
  const CACHE_FILE = process.env.CACHE_FILE || '/data/stats/honeypot_cache.json';
  const ARCHIVED_FILES_PATH = process.env.ARCHIVED_FILES_PATH || '/data/stats/archived_files.json';

  // Cache: file hash -> HoneypotState (avoids re-processing unchanged log files)
  const stateCache = {};
  // Load cache from disk if it exists
  try{ if(fs.existsSync(CACHE_FILE)){ const raw = JSON.parse(fs.readFileSync(CACHE_FILE)); for(const k in raw) { const s = new HoneypotState(); Object.assign(s, raw[k]); stateCache[k]=s; } } }catch(e){/*ignore*/}

  // Load GeoIP database for IP-to-country lookups, but only initialize once.
  if(!geoipInitDone){
    geoipInitDone = true;
    try{
      maxmind = require('maxmind');
      geoLookup = await maxmind.open(GEOIP_DB_PATH);
      geoipAvailable = true;
    }catch(_) {
      // Silently disable GeoIP when maxmind or DB is unavailable.
      geoLookup = null;
      geoipAvailable = false;
    }
  }

  // Helper: lookup country for an IP address using GeoIP database
  function geoipCountry(ip){
    try{
      if(isPrivateIp(ip)) return 'Private IP';
      if(!geoipAvailable || !geoLookup) return null;
      const res = geoLookup.get(ip);
      return res && res.country && res.country.names && (res.country.names.en || res.country.name) || null;
    }catch(e){ return null }
  }

  // Find all Cowrie log files (JSON format)
  const files = fs.existsSync(LOG_DIRECTORY) ? fs.readdirSync(LOG_DIRECTORY).filter(f=>f.startsWith('cowrie.json')) : [];
  if(!files.length) return new HoneypotState();

  // Track which files have been archived (rotated)
  const archived = fs.existsSync(ARCHIVED_FILES_PATH) ? JSON.parse(fs.readFileSync(ARCHIVED_FILES_PATH)) : {};

  // Process a single log file and extract statistics
  const processFile = (filePath)=>{
    const state = new HoneypotState();
    const session_commands = Object.create(null);  // Track commands by session for AI detection
    try{
      const full = fs.readFileSync(filePath,'utf8');
      const lines = full.split(/\r?\n/);
      lines.forEach(line=>{
        if(!line) return;
        try{
          const log_entry = JSON.parse(line);
          const src_ip = log_entry.src_ip;
          // Exclude known IPs (testing/internal)
          if(src_ip && ['149.3.60.167','213.134.160.192','80.85.142.57'].includes(src_ip)) return;
          const eventid = log_entry.eventid;
          const timestamp = log_entry.timestamp ? DateTime.fromISO(log_entry.timestamp) : null;
          
          // Count all new sessions as attacks
          if(eventid === 'cowrie.session.connect' && src_ip && timestamp){
            const month = timestamp.toFormat('yyyy-MM');
            inc(state.attack_counts, src_ip);
            inc(state.monthly_total, month);
            const country = geoipCountry(src_ip);
            if(country) inc(state.geolocation_data, country);
          } 
          // Collect commands for each session (used later to detect AI by command timing)
          else if(eventid === 'cowrie.command.input' && timestamp){
            const session = log_entry.session;
            const input = log_entry.input || '';
            session_commands[session] = session_commands[session] || [];
            session_commands[session].push({ts: timestamp, input});
          }

          // Detect potential AI agents by matching honeypot command signatures
          const input_text = log_entry.input || '';
          if(src_ip && input_text && AI_AGENT_PATTERN.test(input_text)){
            inc(state.ai_agent_attack_counts, src_ip);
            const country = geoipCountry(src_ip);
            if(country) inc(state.ai_agent_geolocation_data, country);
            const month = timestamp ? timestamp.toFormat('yyyy-MM') : 'unknown';
            state.llm_hacking_agents += 1;  // Suspected LLM agent
            inc(state.monthly_ai, month);
          }
        }catch(e){ /* ignore line parse */ }
      });

      // Verify AI agents using command timing heuristic
      // Real AI agents execute commands much faster than humans (median < 2 seconds between commands)
      for(const sess in session_commands){
        const cmds = session_commands[sess].sort((a,b)=>a.ts - b.ts);
        if(cmds.length<=1) continue;  // Need multiple commands for timing analysis
        
        // Calculate time intervals between consecutive commands (in seconds)
        const intervals = [];
        for(let i=0;i<cmds.length-1;i++) intervals.push((cmds[i+1].ts - cmds[i].ts)/1000);
        
        // If median interval < 2 seconds, likely an AI agent (humans are much slower)
        if(median(intervals) < 2.0){
          state.verified_llm_agents += 1;
          const month = cmds[0].ts.toFormat('yyyy-MM');
          inc(state.monthly_verified_ai, month);
          // Attribute this verified detection to all suspected AI agent IPs in this file
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

  // Process all log files (use cache when possible to avoid re-parsing)
  const states = [];
  for(const f of files){
    const full = path.join(LOG_DIRECTORY,f);
    const data = fs.readFileSync(full);
    // Hash the file content to detect if it's been modified
    const h = xxhash.h64().update(data).digest().toString(16);
    // Track rotated log files as archived
    if(/^cowrie.json\.[0-9]+/.test(f)) archived[f]=h;
    // Use cached result if file hasn't changed
    if(stateCache[h]){ states.push(stateCache[h]); continue; }
    // Parse file and cache the result
    const s = processFile(full);
    stateCache[h]=s;
    states.push(s);
  }

  // Combine all per-file stats into one aggregated state
  let final = new HoneypotState();
  for(const s of states) final = final.merge(s);

  // Save cache and archived file list to disk for next run
  try{ fs.writeFileSync(CACHE_FILE, JSON.stringify(Object.fromEntries(Object.entries(stateCache).map(([k,v])=>[k,v.toJSON()]))) ); }catch(e){}
  try{ fs.writeFileSync(ARCHIVED_FILES_PATH, JSON.stringify(archived)); }catch(e){}

  return final;
}

module.exports = { process_logs, HoneypotState };
