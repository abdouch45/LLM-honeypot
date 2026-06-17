const express = require('express');
const path = require('path');
const fs = require('fs');
const chokidar = require('chokidar');  // File system watcher for live reloading
const ejs = require('ejs');             // Template engine for rendering HTML
const { process_logs } = require('./logProcessors/processLogs');

// Configuration: paths and ports
const LOG_DIRECTORY = process.env.LOG_DIRECTORY || '/home/cowrie/cowrie/var/log/cowrie';
const LOG_PATHS = {
  cowrie: LOG_DIRECTORY,
  ftp: process.env.FTP_LOG_FILE || '/data/ftp/ftp_commands.json',
  db: process.env.DB_LOG_FILE || '/data/db/general.log',
  api: process.env.API_LOG_FILE || '/data/api/requests.json',
  dns: process.env.DNS_LOG_FILE || '/data/dns/dns_queries.json',
  webserver: process.env.WEBSERVER_LOG_FILE || '/data/webserver/logs.json',
};
const WATCHED_PATHS = [LOG_PATHS.cowrie, LOG_PATHS.ftp, LOG_PATHS.db, LOG_PATHS.api, LOG_PATHS.dns, LOG_PATHS.webserver];
const TEMPLATE_DIR = path.join(process.cwd(),'templates');  // Where EJS templates live
const PORT = parseInt(process.env.PORT || '8000',10);

// Global cache: store the latest honeypot state in memory (no disk write needed)
let currentState = null;

// Update honeypot data by processing logs (keeps data in memory, no disk write)
async function updateHoneypotData(){
  try{
    // Parse honeypot logs to extract latest statistics
    currentState = await process_logs(LOG_PATHS);
    console.log('Updated honeypot data at', new Date().toISOString());
    
    // Notify connected clients about the update (for live reloading)
    try{
      if(typeof global !== 'undefined' && global.sseClients){
        // The dashboard now renders six independent service tabs; rather than
        // patch every tab's DOM in place over SSE, just tell clients to reload.
        global.sseClients.forEach(r=>{
          try{ r.write(`data: ${JSON.stringify({type:'reload', t:Date.now()})}\n\n`); }catch(e){}
        });
      }
    }catch(e){ /* ignore */ }
  }catch(e){ console.error('Update failed', e); }
}

async function main(){
  // Initialize honeypot data on startup
  await updateHoneypotData();

  const app = express();
  // SSE clients for live-reload notifications
  let sseClients = [];
  // expose to updateHoneypotData() scope via global so notification code can access
  global.sseClients = sseClients;
  
  // Serve static files: images, CSS, JS from /web/static directory
  app.use(express.static(path.join(process.cwd(), 'static')));
  
  // SSE (Server-Sent Events) endpoint for live reload notifications
  app.get('/events', (req, res) => {
    res.set({
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive'
    });
    res.flushHeaders && res.flushHeaders();
    // send a comment to keep connection alive for some proxies
    res.write(': connected\n\n');
    // Add this client to the notification list
    sseClients.push(res);
    // Remove client when connection closes
    req.on('close', () => {
      sseClients = sseClients.filter(r => r !== res);
    });
  });

  // Main page route - render template on-demand with current state
  app.get('/', (req, res) => {
    try{
      const context = currentState ? currentState.prepare_template_data() : {};
      const tplPath = path.join(TEMPLATE_DIR, 'main', 'index.html');
      const tplSrc = fs.readFileSync(tplPath, 'utf8');
      const html = ejs.render(tplSrc, context, {filename: tplPath});
      res.send(html);
    }catch(e){
      console.error('render error', e.message);
      res.status(500).send('Error rendering page');
    }
  });
  
  // Explainer page route - render template on-demand with current state
  app.get('/explainer', (req, res) => {
    try{
      const context = currentState ? currentState.prepare_template_data() : {};
      const tplPath = path.join(TEMPLATE_DIR, 'main', 'explainer.html');
      const tplSrc = fs.readFileSync(tplPath, 'utf8');
      const html = ejs.render(tplSrc, context, {filename: tplPath});
      res.send(html);
    }catch(e){
      console.error('render error', e.message);
      res.status(500).send('Error rendering page');
    }
  });

  // Manual update endpoint (optional, can be called to force data refresh)
  app.get('/regenerate', async (req,res)=>{
    await updateHoneypotData();
    res.send('ok');
  });

  // Start the server
  const server = app.listen(PORT, '0.0.0.0', ()=> console.log('Server listening on', PORT));

  // Watch every service's log directory/file for changes and update honeypot data
  const watcher = chokidar.watch(WATCHED_PATHS, {ignoreInitial:true, depth:1});
  let busy = false;
  watcher.on('all', async (ev, logPath)=>{
    if(busy) return;  // Prevent simultaneous updates
    busy = true;
    console.log('Detected change', ev, logPath);
    try{ await updateHoneypotData(); }catch(e){ console.error(e); }
    busy = false;
  });
}

main().catch(e=>{ console.error(e); process.exit(1); });
