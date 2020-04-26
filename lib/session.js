const { EventEmitter } = require('events');

const { debuglog } = require('util');

const debug = debuglog('ProxyAgent');

class CredentialsCache {
  constructor(lookup) {
    if (lookup) {
      this.lookupCredentials = lookup;
    }
    this.cacheCredentials = {};
  }

  lookupCredentials() {
    return Promise.resolve({});
  }

  setCredentials(host, credentials) {
    this.cacheCredentials[host] = Promise.resolve(credentials);
  }

  findCredentials(host) {
    if (this.cacheCredentials[host] === undefined) {
      this.cacheCredentials[host] = this.lookupCredentials(host)
        .then(credentials => {
          debug(`proxy authenticated host=${host}`);
          return credentials;
        })
        .catch(() => {
          debug(`proxy unauthenticated host=${host}`);
          return {};
        });
    }
    return this.cacheCredentials[host];
  }
}

class Session extends EventEmitter {
  constructor(resolver, credentials) {
    super();
    this.resolver = resolver;
    this.credentials = credentials || new CredentialsCache();
    this.valid = {};
  }

  isEnabled() {
    return !!this.resolver;
  }

  addCredentials(host, credentials) {
    this.credentials.setCredentials(host, credentials);
  }

  setCredentialsCache(cache) {
    // Reload passwords, reset valid flags.
    this.credentials = cache;
    this.valid = {};
  }

  setResolver(resolver) {
    this.resolver = resolver;
  }

  onError({ host, callback }) {
    this.valid[host] = false;
    callback();
    return true; // We handle it.
  }

  // Return null for direct connection, {} for error.
  proxyForUrl(url) {
    if (!this.resolver) {
      return Promise.resolve(null);
    }
    return this.resolver.resolve(url)
      .catch(() => null)
      .then(proxies => {
        if (proxies && (typeof proxies === 'string' || proxies.host)) {
          return [proxies];
        }
        return proxies;
      })
      .then(proxies => this.searchProxies(proxies));
  }

  searchProxies(proxies) {
    if (!this.resolver) {
      return Promise.resolve(null);
    }
    if (!proxies) {
      return Promise.resolve(null);
    }
    for (let i = 0; i < proxies.length; i++) {
      const proxyUrl = this.resolver.getProxy(proxies[i]);
      const proxy = this.resolver.parseProxy(proxyUrl);
      if (!proxy) {
        return Promise.resolve(null);
      }
      const { host, port, protocol } = proxy;
      if (this.valid[host] !== false) {
        return this.credentials.findCredentials(host)
          .then(credentials => {
            if (credentials.username) {
              return credentials;
            }
            return {};
          })
          .then(credentials => {
            const { username, password } = credentials;
            let proxyAuth;
            if (username) {
              proxyAuth = password ? `${username}:${password}` : username;
            }
            return {
              host,
              port,
              protocol,
              proxyAuth,
            };
          });
      }
    }
    // No valid proxies found.
    return Promise.resolve({});
  }
}

module.exports = {
  CredentialsCache,
  Session,
};
