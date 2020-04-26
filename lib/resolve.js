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
    if (options.host) {
      this.proxy = this.parseProxy(options.host);
      if (options.port) {
        this.proxy.port = options.port;
      }
      if (!this.proxy.protocol) {
        this.proxy.protocol = 'http:';
      }
      if (!this.proxy.port) {
        this.proxy.port = ProxyResolver.defaultPort(this.proxy);
      }
    }
  }

  static defaultPort(proxy) {
    return ['http:', 'https:'].includes(proxy.protocol || 'http:') ? 8080 : 1080;
  }

  // We need to parse URLs with or without a protocol.
  static parseUrl(url) {
    const match = url.match(/((?<protocol>\w+:)[/][/])?((?<username>[^:@]+)(:(?<password>[^@]+))?@)?(?<host>[^: ]+)(:(?<port>\d+))?/);
    if (match) {
      const result = { ...match.groups };
      if (result.port) {
        result.port = parseInt(result.port, 10);
      }
      return result;
    }
  }

  parseProxy(proxyUrl) {
    if (typeof proxyUrl !== 'string') {
      return proxyUrl;
    }
    return ProxyResolver.parseUrl(proxyUrl) || {};
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

// Simple set of proxy options
class ProxyResolverProtocol extends ProxyResolver {
  constructor(options = {}) {
    super(options);
    this.https = options.https;
    this.http = options.http;
    this.socks = options.socks;
  }

  resolve(targetUrl) {
    if (this.isBypass(targetUrl)) {
      return Promise.resolve(null);
    }
    if (this.socks) {
      return Promise.resolve(this.socks);
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

// Parse results on Windows, as from
// WinHttpGetDefaultProxyConfiguration
class ProxyResolverWindows extends ProxyResolver {
  constructor(options = {}) {
    super(options);
    this.proxies = [];
    const proxies = options.proxies.split(/;|\s+/);
    const protocols = ['http', 'https', 'socks', 'socks4', 'socks4a', 'socks5', 'socks5h'];
    proxies.forEach(p => {
      const match = p.match(/((?<scheme>\w+)=)?((?<protocol>\w+:)[/][/])?((?<username>[^:@]+)(:(?<password>[^@]+))?@)?(?<host>[^: ]+)(:(?<port>\d+))?/);
      if (match) {
        const { scheme, host, port } = match.groups;
        const protocol = match.groups.protocol || `${scheme || 'http'}:`;
        if (protocols.includes(protocol)) {
          this.proxies.push({
            protocol,
            host,
            port: port || ProxyResolver.defaultPort({ protocol }),
          });
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

// Proxy Auto Config file, either on disk or network
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
      if (s[0] === 'SOCKS') {
        return 'socks://' + s[1];
      }
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

const loadPac = (url, options = {}) => {
  if (url.startsWith('file://')) {
    return new Promise(resolve => {
      fs.readFile(url.substring(7), (err, data) => {
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
    httpGet = u => (
      new Promise((resolve, reject) => {
        http.get(u, (err, data) => {
          if (err) {
            reject(err);
          } else {
            resolve(data);
          }
        });
      })
    );
  }
  return Promise.resolve().then(() => {
    return httpGet(url)
      .catch(e => {
        debug(e);
        return null; // Revert to direct connection
      });
  });
};

const discoverProxy = (proxy, options = {}) => {
  if (proxy) {
    debug('proxy system settings', proxy);
  }
  if (!proxy) {
    return null;
  } if (proxy.pac) {
    return new ProxyResolverPAC(proxy.pac);
  } if (proxy.url) {
    return loadPac(proxy.url, options)
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
  if (proxy.host) {
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
