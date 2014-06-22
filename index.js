(function() {
  'use strict';

  var express = require('express');
  var http = require('http');
  var querystring = require('querystring');
  var fs = require('fs');

  /**
   * KeyAuthConsumer Constructor
   */
  var KeyAuthConsumer = function(data) {
    this.http = 'http';
    this.name = data.name;
    this.about = data.about;
    this.redirect = data.redirect;

    // Load public RSA key
    fs.readFile(data.key, function(err, data) {
      this.key = data;
    }.bind(this));

    // Load avatar
    fs.readFile(data.avatar, function(err, data) {
      this.avatar = data;
    }.bind(this));
  };

  /**
   * Generate redirect URL for given provider
   */
  KeyAuthConsumer.prototype.providerURL = function(name) {
    return this.http + '://' + name + '/auth?client_id=' + this.name + '&response_type=token&scope=auth';
  };

  /**
   * Helper for sending HTTP post request
   */
  KeyAuthConsumer.prototype.postHTTP = function(options, data, callback) {
    var handle = function(response) {
      var data = '';

      response.on('data', function(chunk) {
        data += chunk;
      });

      response.on('end', function() {
        callback(data);
      });
    };

    var req = http.request(options, handle);
    req.write(data);
    req.end();
  };

  /**
   * Handle callback from KeyAuthProvider
   */
  KeyAuthConsumer.prototype.validateCallback = function(provider, token, callback) {
    // Provider parsing
    var prov = provider.split(':');
    var provName = prov.shift();
    var provPort = prov.shift();

    // Post request data
    var data = querystring.stringify({token: token, 'client_id': this.name});

    // Post request options
    var options = {
      host: provName,
      path: '/auth/validate',
      port: provPort || 80,
      method: 'post',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(data)
      }
    };

    this.postHTTP(options, data, function(data) {
      var json = {};
      try {
        json = JSON.parse(data);
      } catch (e) { }

      callback(!!json.valid, json.token);
    });
  };

  /**
   * Request session from KeyAuthProvider after handling auth callback
   */
  KeyAuthConsumer.prototype.getSession = function(provider, token, callback) {
    // Provider parsing
    var prov = provider.split(':');
    var provName = prov.shift();
    var provPort = prov.shift();

    // Post request data
    var data = querystring.stringify({token: token, 'client_id': this.name});

    var options = {
      host: provName,
      path: '/auth/session',
      port: provPort || 80,
      method: 'post',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(data)
      }
    };

    this.postHTTP(options, data, function(data) {
      var json = {};
      try {
        json = JSON.parse(data);
      } catch (e) { }

      callback(json.name ? null : true, json);
    });
  };

  /**
   * Set up express routes for handling login
   */
  KeyAuthConsumer.prototype.handleLogin = function() {
    var router = express.Router();

    // Redirect user to given KeyAuth provider
    router.post('/', function(req, res) {
      res.redirect(this.providerURL(req.body.username));
    }.bind(this));

    // Handle redirect from KeyAuth provider
    router.get('/callback', function(req, res) {
      // Check given token
      this.validateCallback(req.param('provider'), req.param('token'), function(valid, token) {
        if (valid && token) {
          // Validate user session
          this.getSession(req.param('provider'), token, function(err, user) {
            // Check session response
            if (!err && user) {
              req.session.keyauth = {valid: true, user: user};

              res.redirect(this.redirect);
            } else {
              res.end('Cannot fetch session. Too bad!');
            }
          }.bind(this));
        } else {
          res.end('Cannot validate token. I\'m sorry!');
        }
      }.bind(this));
    }.bind(this));

    return router;
  };

  /**
   * Handle /about request with information about this consumer instance
   */
  KeyAuthConsumer.prototype.handleAbout = function() {
    return function(req, res) {
      res.json({
        name: this.name,
        about: this.about,
        key: '/key',
        avatar: '/avatar'
      });
    }.bind(this);
  };

  /**
   * Handle request for consumer avatar
   */
  KeyAuthConsumer.prototype.handleAvatar = function() {
    return function(req, res) {
      res.write(this.avatar);
      res.end();
    }.bind(this);
  };

  /**
   * Handle request for consumer rsa public key
   */
  KeyAuthConsumer.prototype.handleKey = function() {
    return function(req, res) {
      res.write(this.key);
      res.end();
    }.bind(this);
  };

  /**
   * Export session data to response locals
   */
  KeyAuthConsumer.prototype.exportSession = function() {
    return function(req, res, next) {
      if (req.session.keyauth && req.session.keyauth.valid) {
        res.locals.user = req.session.keyauth.user;
      }

      next();
    };
  };

  /**
   * Export logout handler
   */
  KeyAuthConsumer.prototype.exportLogout = function() {
    return function(req, res, next) {
      if (!res.keyauth) {
        res.keyauth = {};
      }

      // Export method on response object
      res.keyauth.logout = function(path) {
        req.session.keyauth = {valid: false, user: null};

        if (path) {
          res.redirect(path);
        }
      };

      next();
    };
  };

  /**
   * Bind express routes
   */
  KeyAuthConsumer.prototype.expressBinding = function() {
    var router = express.Router();

    // Basic profile JSON
    router.get('/about',   this.handleAbout());

    // Avatar image
    router.get('/avatar',  this.handleAvatar());

    // Public RSA key
    router.get('/key',     this.handleKey());

    // Bind routing for login handling
    router.use('/login',   this.handleLogin());

    // Export session data to locals
    router.use(this.exportSession());

    // Export logout function
    router.use(this.exportLogout());

    return router;
  };

  module.exports = KeyAuthConsumer;
})();
