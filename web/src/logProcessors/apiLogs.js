const fs = require('fs');
const path = require('path');
const { DateTime } = require('luxon');

function parseApiLine(line) {
  try {
    return JSON.parse(line);
  } catch (e) {
    return null;
  }
}

function summarizeApiLogs(lines) {
  const summary = {
    total_requests: 0,
    per_path: {},
    per_agent: {},
    status_counts: {},
    first_seen: null,
    last_seen: null,
  };

  for (const line of lines) {
    const entry = parseApiLine(line);
    if (!entry) continue;
    summary.total_requests += 1;
    const path = entry.path || 'unknown';
    const agent = entry.agent || 'unknown';
    const status = entry.status || 'unknown';
    summary.per_path[path] = (summary.per_path[path] || 0) + 1;
    summary.per_agent[agent] = (summary.per_agent[agent] || 0) + 1;
    summary.status_counts[status] = (summary.status_counts[status] || 0) + 1;
    const ts = entry.timestamp ? DateTime.fromISO(entry.timestamp) : null;
    if (ts && ts.isValid) {
      if (!summary.first_seen || ts < summary.first_seen) summary.first_seen = ts;
      if (!summary.last_seen || ts > summary.last_seen) summary.last_seen = ts;
    }
  }

  return summary;
}

module.exports = { summarizeApiLogs };
