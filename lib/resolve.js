const pacResolver = require('pac-resolver');
const fs = require('fs');
const http = require('http');
const { debuglog } = require('util');

const debug = debuglog('ProxyAgent');

class ProxyResolver {
  constructor(options = {}) {
    this.bypass = options.bypass;
    if (typeof this.bypass === 'string') {
      this.bypass = this.bypass.split(/;|\s+/);
    }
    if (options.server && options.port) {
      this.proxy = `${options.server}:${options.port}`;
    }
  }

  isBypass(targetUrl) {
    if (!this.bypass || this.bypass.length === 0) {
      return false;
    }
    const u = new URL(targetUrl);
    const { hostname } = u;
    for (let i = 0; i < this.bypass.length; i++) {
      const bypass = this.bypass[i];
      if (bypass === '<local>' && !hostname.includes('.')) {
        debug(`proxy bypass hostname=${hostname}: simple hostname`);
        return true;
      }
      if (bypass === hostname) {
        debug(`proxy bypass hostname=${hostname}: ${bypass}`);
        return true;
      }
      if (bypass.charAt(0) === '*' && hostname.endsWith(bypass.slice(1))) {
        debug(`proxy bypass hostname=${hostname}: ${bypass}`);
        return true;
      }
      if (bypass.endsWith('*')
          && hostname.startsWith(bypass.slice(0, bypass.length - 2))) {
        debug(`proxy bypass hostname=${hostname}: ${bypass}`);
        return true;
      }
      if (/^[0-9.]*\/[0-9]+/.test(bypass)
          && hostname.startsWith(bypass.split('/')[0])) {
        // Hack to handle cases like 192.168/16
        debug(`proxy bypass hostname=${hostname}: ${bypass}`);
        return true;
      }
    }
    return false;
  }

  getProxy(proxy) {
    return proxy;
  }

  parseProxy(proxyUrl) {
    if (typeof proxyUrl !== 'string') {
      return proxyUrl;
    }
    try {
      const u = new URL(proxyUrl);
      const { hostname, password, port, username } = u;
      return {
        host: hostname,
        port,
        username,
        password,
      };
    } catch (err) {
      const m = /([^:]+)(?:[:]([0-9]+))?/.exec(proxyUrl);
      const host = m[1];
      const port = m[2];
      if (host && m.index === 0) {
        return { host, port };
      }
    }
    return {};
  }

  resolve(targetUrl) {
    if (!this.proxy) {
      return Promise.resolve(null);
    }
    if (this.isBypass(targetUrl)) {
      return Promise.resolve(null);
    }
    return Promise.resolve(this.proxy);
  }
}

class ProxyResolverProtocol extends ProxyResolver {
  constructor(options = {}) {
    super(options);
    this.https = options.https;
    this.http = options.http;
  }

  resolve(targetUrl) {
    if (this.isBypass(targetUrl)) {
      return Promise.resolve(null);
    }
    if (targetUrl.startsWith('http://')) {
      return Promise.resolve(this.http);
    }
    if (targetUrl.startsWith('https://')) {
      return Promise.resolve(this.https);
    }
    return Promise.resolve(this.https || this.http || null);
  }
}

class ProxyResolverWindows extends ProxyResolver {
  constructor(options = {}) {
    super(options);
    this.proxies = [];
    const proxies = options.proxies.split(/;|\s+/);
    proxies.forEach(p => {
      const match = p.match(/(\w+=)?(\w+:[/][/])?([^: ]+)(:\d+)?/);
      if (match) {
        const [whole, label, protocol, server, port] = match;
        const m = { whole, label, protocol, server, port };
        if (m.label === 'http='
            || m.protocol === 'http://'
            || (m.label === 'https=' || m.protocol === 'https://')
            || (!m.label && !m.protocol)) {
          this.proxies.push(`${m.server}${m.port || ':8080'}`);
        }
      }
    });
  }

  resolve(targetUrl) {
    if (this.isBypass(targetUrl)) {
      return Promise.resolve(null);
    }
    return Promise.resolve(this.proxies);
  }
}

class ProxyResolverPAC extends ProxyResolver {
  constructor(options = {}) {
    super(options);
    this.pac = options.pac;
  }

  getProxy(proxy) {
    if (proxy.trim() === 'DIRECT') {
      return null;
    }
    const s = proxy.trim().split(/\s+/);
    if (s.length > 1 && ['PROXY', 'SOCKS'].includes(s[0])) {
      return s[1];
    }
    return null;
  }

  resolve(targetUrl) {
    if (this.isBypass(targetUrl)) {
      return Promise.resolve(null);
    }
    return pacResolver(this.pac)(targetUrl)
      .catch(() => null)
      .then(res => res.split(/;/));
  }
}

const discoverProxy = (proxy, options = {}) => {
  if (proxy) {
    debug('proxy system settings', proxy);
  }
  if (!proxy) {
    return null;
  } if (proxy.pac) {
    return new ProxyResolverPAC(proxy);
  } if (proxy.url) {
    return Promise.resolve().then(() => {
      if (proxy.url.startsWith('file://')) {
        return new Promise(resolve => {
          fs.readFile(proxy.url.substring(7), (err, data) => {
            if (err) {
              debug(err);
              resolve(null); // Revert to direct connection
            } else {
              resolve(data);
            }
          });
        });
      }
      let { httpGet } = options;
      if (!httpGet) {
        httpGet = url => (
          new Promise((resolve, reject) => {
            http.get(url, (err, data) => {
              if (err) {
                reject(err);
              } else {
                resolve(data);
              }
            });
          })
        );
      }
      return httpGet(proxy.url)
        .catch(e => {
          debug(e);
          return null; // Revert to direct connection
        });
    })
      .then(body => {
        if (body) {
          return new ProxyResolverPAC({ pac: body, bypass: proxy.bypass });
        }
        return null; // Assume direct connection
      });
  }
  if (proxy.proxies) {
    // Parse results on Windows.
    return new ProxyResolverWindows(proxy);
  }
  if (proxy.http || proxy.https) {
    // Parse results on Mac.
    return new ProxyResolverProtocol(proxy);
  }
  if (proxy.host && proxy.port) {
    // Manual settings.
    return new ProxyResolver(proxy);
  }
  return null;
};

module.exports = {
  ProxyResolver,
  ProxyResolverProtocol,
  ProxyResolverWindows,
  ProxyResolverPAC,
  discoverProxy,
};
