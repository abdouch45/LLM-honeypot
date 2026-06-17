const path = require('path');
const { isPrivateIp } = require('./honeypotState');

let maxmind;
let geoipInitDone = false;
let geoipAvailable = false;
let geoLookup = null;

// Load the GeoIP database once and reuse it across every service processor.
async function initGeoip(){
  if(geoipInitDone) return;
  geoipInitDone = true;
  const GEOIP_DB_PATH = process.env.GEOIP_DB_PATH || path.join(process.cwd(),'GeoLite2-Country.mmdb');
  try{
    maxmind = require('maxmind');
    geoLookup = await maxmind.open(GEOIP_DB_PATH);
    geoipAvailable = true;
  }catch(_){
    geoLookup = null;
    geoipAvailable = false;
  }
}

// Lookup country for an IP address. Returns 'Private IP' for RFC1918/loopback
// addresses, null when the value isn't a routable IP or GeoIP is unavailable.
function geoipCountry(ip){
  try{
    if(!ip) return null;
    if(isPrivateIp(ip)) return 'Private IP';
    if(!geoipAvailable || !geoLookup) return null;
    const res = geoLookup.get(ip);
    return res && res.country && res.country.names && (res.country.names.en || res.country.name) || null;
  }catch(e){ return null }
}

module.exports = { initGeoip, geoipCountry };
