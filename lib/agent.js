// Originally based on (but mostly rewritten):
// https://github.com/koichik/node-tunnel

const net = require('net');
const tls = require('tls');
const http = require('http');
const { debuglog } = require('util');
const { EventEmitter } = require('events');

const debug = debuglog('ProxyAgent');

// Borrowed function from:
// https://github.com/TooTallNate/node-agent-base/blob/master/src/index.ts
const isSecureEndpoint = () => {
  const { stack } = new Error();
  if (typeof stack !== 'string') return false;
  return stack.split('\n').some(l => l.indexOf('(https.js:') !== -1);
};

class HttpProxyAgent extends EventEmitter {
  constructor(options = {}) {
    super();
    this.options = options || {};
    this.maxSockets = this.options.maxSockets || http.Agent.defaultMaxSockets;
    this.requests = [];
    this.sockets = [];
    this.request = http.request;

    this.proxyOptions = {
      protocol: 'http:',
      ...(this.options.proxy || {}),
      method: 'CONNECT',
    };
    this.session = this.options.session;

    this.on('free', (socket, host) => {
      for (let i = 0, len = this.requests.length; i < len; ++i) {
        const pending = this.requests[i];
        if (pending.host === host.host && pending.port === host.port) {
          // Detect the request to connect same origin server,
          // reuse the connection.
          this.requests.splice(i, 1);
          pending.request.onSocket(socket);
          return;
        }
      }
      socket.destroy();
      this.removeSocket(socket);
    });
  }

  isSecureEndpoint() {
    return (this.options.tls !== undefined) ? this.options.tls : isSecureEndpoint();
  }

  get defaultPort() {
    if (typeof this.explicitDefaultPort === 'number') {
      return this.explicitDefaultPort;
    }
    return this.isSecureEndpoint() ? 443 : 80;
  }

  set defaultPort(v) {
    this.explicitDefaultPort = v;
  }

  get protocol() {
    if (typeof this.explicitProtocol === 'string') {
      return this.explicitProtocol;
    }
    return this.isSecureEndpoint() ? 'https:' : 'http:';
  }

  set protocol(v) {
    this.explicitProtocol = v;
  }

  addRequest(req, host) {
    const options = { request: req, ...this.options, ...host };

    if (this.sockets.length >= this.maxSockets) {
      // We are over limit so we'll add it to the queue.
      this.requests.push(options);
      return;
    }

    // If we are under maxSockets create a new one.
    this.createSocket(options, socket => {
      const self = this;
      function onFree() {
        self.emit('free', socket, options);
      }
      function onCloseOrRemove() {
        self.removeSocket(socket);
        socket.removeListener('free', onFree);
        socket.removeListener('close', onCloseOrRemove);
        socket.removeListener('agentRemove', onCloseOrRemove);
      }
      socket.on('free', onFree);
      socket.on('close', onCloseOrRemove);
      socket.on('agentRemove', onCloseOrRemove);
      req.onSocket(socket);
    });
  }

  createSocket(options, cb) {
    const opts = { ...options };
    if (opts.secureEndpoint === undefined) {
      opts.secureEndpoint = this.options.tls;
    }
    if (opts.secureEndpoint === undefined) {
      opts.secureEndpoint = isSecureEndpoint();
    }
    if (!opts.secureEndpoint) {
      return this.createHttpSocket(options, cb);
    }
    this.createHttpSocket(options, socket => {
      const hostHeader = options.request.getHeader('host');
      const tlsOptions = {
        ...(this.options.tlsOptions || {}),
        socket,
        servername: hostHeader ? hostHeader.replace(/:.*$/, '') : options.host
      };

      const secureSocket = tls.connect(tlsOptions);
      this.sockets[this.sockets.indexOf(socket)] = secureSocket;
      cb(secureSocket);
    });
  }

  createHttpSocket(options, cb) {
    const { host } = options;
    const protocol = this.options.protocol || (options.secureEndpoint ? 'https:' : 'http:');
    const path = `${host}:${options.port}`;
    const url = `${protocol}//${path}`;
    Promise.resolve()
      .then(() => {
        if (this.session) {
          return this.session.proxyForUrl(url);
        }
        return {};
      })
      .then(proxy => {
        if (proxy) {
          this.createSocketWithProxy(options, proxy, cb);
        } else {
          // direct connection
          net.connect(options, cb);
        }
      });
  }

  createSocketWithProxy(options, proxyOptions, cb) {
    const { host } = options;
    const path = `${host}:${options.port}`;
    const placeholder = {};
    this.sockets.push(placeholder);

    const connectOptions = {
      ...this.proxyOptions,
      ...(proxyOptions || {}),
      method: 'CONNECT',
      path,
      agent: false,
      headers: {
        host: path,
      }
    };
    const proxyHost = connectOptions.host;
    if (!proxyHost) {
      // Proxy was not configured, or we ran out of proxies to try.
      const error = new Error('tunneling socket could not be established, '
                              + 'cause=No proxy');
      error.code = 'ECONNRESET';
      options.request.emit('error', error);
    }
    if (options.localAddress) {
      connectOptions.localAddress = options.localAddress;
    }
    const { proxyAuth } = connectOptions;
    if (proxyAuth) {
      connectOptions.headers = connectOptions.headers || {};
      const authStr = 'Basic ' + Buffer.from(proxyAuth).toString('base64');
      connectOptions.headers['Proxy-Authorization'] = authStr;
    }

    debug('making CONNECT request');
    const connectReq = this.request(connectOptions);
    connectReq.once('error', cause => {
      connectReq.removeAllListeners();

      debug('tunneling socket could not be established, cause=%s\n', cause.message, cause.stack);
      const error = new Error('tunneling socket could not be established, '
                              + 'cause=' + cause.message);
      error.code = 'ECONNRESET';
      options.request.emit('error', error);
      this.removeSocket(placeholder);
    });
    connectReq.once('connect', (response, socket, head) => {
      connectReq.removeAllListeners();
      socket.removeAllListeners();

      const onRetry = () => {
        this.createSocket(options, cb);
      };
      if (response.statusCode === 407) {
        const { headers } = response;
        const authHeader = headers && headers['proxy-authenticate'];
        let realm = authHeader && authHeader.match(/realm="([^"]*)"/);
        realm = realm && realm[1];
        realm = realm || proxyHost;

        debug('tunneling socket requires authentication, realm=%s', realm);
        socket.destroy();
        this.removeSocket(placeholder);

        const payload = { host: proxyHost, realm, callback: onRetry };
        if (this.session && this.session.emit('proxyAuthenticate', payload)) {
          // We have listeners so wait for authentication.
          return;
        }
      }
      if (response.statusCode !== 200) {
        debug('tunneling socket could not be established, statusCode=%d', response.statusCode);
        socket.destroy();
        this.removeSocket(placeholder);

        const error = new Error('tunneling socket could not be established, '
                                + 'statusCode=' + response.statusCode);
        error.code = 'ECONNRESET';
        const payload = { host: proxyHost, error, callback: onRetry };
        if (this.session
            && (this.session.onError(payload) || this.session.emit('proxyError', payload))) {
          // We have listeners so wait to try another proxy.
          return;
        }
        options.request.emit('error', error);
      } else if (head.length > 0) {
        debug('got illegal response body from proxy');
        socket.destroy();
        this.removeSocket(placeholder);

        const error = new Error('got illegal response body from proxy');
        error.code = 'ECONNRESET';
        const payload = { host: proxyHost, error, callback: onRetry };
        if (this.session
            && (this.session.onError(payload) || this.session.emit('proxyError', payload))) {
          // We have listeners so wait to try another proxy.
          return;
        }
        options.request.emit('error', error);
      } else {
        debug('tunneling connection has established');
        this.sockets[this.sockets.indexOf(placeholder)] = socket;
        return cb(socket);
      }
    });
    connectReq.end();
  }

  removeSocket(socket) {
    const pos = this.sockets.indexOf(socket);
    if (pos === -1) {
      return;
    }
    this.sockets.splice(pos, 1);

    const pending = this.requests.shift();
    if (pending) {
      // If we have pending requests and a socket gets closed a new one
      // needs to be created to take over in the pool for the one that closed.
      this.createSocket(pending, s => {
        pending.request.onSocket(s);
      });
    }
  }
}

class HttpsProxyAgent extends HttpProxyAgent {
  constructor(options = {}) {
    super({ ...options, tls: true });
  }
}

module.exports = {
  HttpProxyAgent,
  HttpsProxyAgent,
};
