const { DateTime } = require('luxon');

// Pattern used to recognize private IP addresses and local hosts
const PRIVATE_IP_PATTERN = /^(?:127\.0\.0\.1|10\.(?:\d{1,3}\.){2}\d{1,3}|192\.168\.(?:\d{1,3}\.)\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.(?:\d{1,3}\.)\d{1,3}|::1|fc00:|fe80:)/i;
function isPrivateIp(ip){ return PRIVATE_IP_PATTERN.test(ip); }

// Utility: create a map object for counting occurrences
function counter() { return Object.create(null); }
// Utility: increment a counter in a map (default increment by 1)
function inc(map, key, n=1){ map[key] = (map[key]||0)+n }

// Calculate the median value of an array (used for detecting AI agents by command timing)
function median(arr){
  if(!arr.length) return 0;
  const s = arr.slice().sort((a,b)=>a-b);
  const mid = Math.floor(s.length/2);
  return s.length%2 ? s[mid] : (s[mid-1]+s[mid])/2;
}

// Generic per-service statistics holder: total interactions, AI agent detections,
// geolocation, and monthly trends. Used identically by every honeypot service
// (cowrie/ftp/db/api/dns/webserver) so the dashboard can render the same kind
// of panel for each of them.
class HoneypotState {
  constructor(){
    // General attack statistics
    this.attack_counts = counter();           // origin -> attack count
    this.geolocation_data = counter();        // Country -> attack count

    // AI agent detection statistics
    this.llm_hacking_agents = 0;              // Total suspected LLM agents
    this.verified_llm_agents = 0;             // Verified LLM agents
    this.ai_agent_attack_counts = counter();  // origin -> AI agent attack count
    this.verified_ai_agent_counts = counter();// origin -> verified AI agent count
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

  // Prepare data for rendering in HTML templates (aggregations, top lists, percentages).
  // origin_label customizes how the "top origins" lists are described per-service
  // (e.g. "IP Address" for cowrie/ftp/webserver/dns/api, "Host" for db).
  prepare_template_data(origin_label='IP Address'){
    const total_attacks = Object.values(this.attack_counts).reduce((a,b)=>a+b,0);
    const month_labels = Object.keys(this.monthly_total).sort();
    const monthly_attacks = month_labels.map(m=> this.monthly_total[m]||0);
    const monthly_ai_attacks = month_labels.map(m=> this.monthly_ai[m]||0);
    const monthly_verified_ai_attacks = month_labels.map(m=> this.monthly_verified_ai[m]||0);

    const top_attackers = Object.entries(this.attack_counts).sort((a,b)=>b[1]-a[1]).slice(0,10);
    const top_ai_agents = Object.entries(this.ai_agent_attack_counts).sort((a,b)=>b[1]-a[1]).slice(0,10);
    const top_verified_ai_agents = Object.entries(this.verified_ai_agent_counts).sort((a,b)=>b[1]-a[1]).slice(0,10);

    const geolocation_percentages = [];
    if(total_attacks>0){
      Object.entries(this.geolocation_data).sort((a,b)=>b[1]-a[1]).slice(0,10).forEach(([country,count])=>{
        geolocation_percentages.push([country, Math.round((count/total_attacks)*10000)/100]);
      });
    }

    const ai_geolocation_percentages = [];
    if(this.llm_hacking_agents>0){
      Object.entries(this.ai_agent_geolocation_data).sort((a,b)=>b[1]-a[1]).slice(0,10).forEach(([country,count])=>{
        ai_geolocation_percentages.push([country, Math.round((count/this.llm_hacking_agents)*10000)/100]);
      });
    }

    const verified_ai_geolocation_percentages = [];
    if(this.verified_llm_agents>0){
      Object.entries(this.verified_ai_geolocation_data).sort((a,b)=>b[1]-a[1]).slice(0,10).forEach(([country,count])=>{
        verified_ai_geolocation_percentages.push([country, Math.round((count/this.verified_llm_agents)*10000)/100]);
      });
    }

    const current_month = DateTime.now().toFormat('yyyy-MM');
    const last_month_incomplete = month_labels.length && month_labels[month_labels.length-1] === current_month;

    return {
      origin_label,
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

module.exports = { HoneypotState, isPrivateIp, counter, inc, median };
