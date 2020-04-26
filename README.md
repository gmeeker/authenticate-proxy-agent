# authenticate-proxy-agent - HTTP/HTTPS/SOCKS agent with authentication messages

Originally based on node-tunnel, although mostly rewritten:

https://github.com/koichik/node-tunnel

## Example

```javascript
// Export a single global session
// Add function to look up passwords by default.
// Add wrapper to deal with global arrow function being undefined.
const cache = new CredentialsCache(host => { username: 'username', password: 'invalid' });
export default new Session(undefined, cache);
```

```javascript
const session = require('./session');

const { CredentialsCache, Session } = require('authenticate-proxy-agent');

// Add a proxy.  Could be a PAC URL instead: { pac: 'http://192.168.1.1' }
session.setResolver(discoverProxy({
  host: '192.168.1.1',
  port: 3128
}));

session.on('proxyAuthenticate', ({ host, realm, callback }) => {
  // Find or prompt for new password, then add credentials or invalidate proxy
  session.addCredentials(host, { username: 'username', password: 'password' });
  callback();
  // or:
  // session.onError({ host, callback })
});

const authAgent = new HttpsProxyAgent({ session });

var req = https.request({
  host: 'example.com',
  port: 443,
  agent: authAgent
});
```
