/**
 *  Copyright 2014 IBM Corp. All Rights Reserved
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

var passportStrategy = require('passport-strategy');
var util = require('util');
var logger = require('log4js').getLogger('mca-website-strategy');
var request = require('request');

var FilterUtil = require('./util/filter-util');
var ERRORS = require("./Errors");

function Strategy(options) {
	var self = this;
	options = options || {};
	var mcaCredentials = FilterUtil.getMcaServiceCredentials();

	this.clientId = (options.clientId) ? options.clientId : mcaCredentials.clientId;
	this.secret = (options.secret) ? options.secret : mcaCredentials.secret;
	this.authorizationEndpoint = (options.authorizationEndpoint) ? options.authorizationEndpoint : mcaCredentials.authorizationEndpoint;
	this.tokenEndpoint = (options.tokenEndpoint) ? options.tokenEndpoint : mcaCredentials.tokenEndpoint;
	this.callbackUrl = options.callbackUrl;

	logger.debug("clientiD", this.clientId);
	logger.debug("secret", this.secret.substr(0, 1) + "............................" + this.secret.substr(this.secret.length - 1));
	logger.debug("authorizationEndpoint", this.authorizationEndpoint);
	logger.debug("tokenEndpoint", this.tokenEndpoint);
	logger.debug("callbackUrl", this.callbackUrl);

	if (typeof(this.clientId) !== "string" ||
		typeof(this.secret) !== "string" ||
		typeof(this.authorizationEndpoint) !== "string" ||
		typeof(this.tokenEndpoint) !== "string" ||
		typeof(this.callbackUrl) !== "string") {
		throw new TypeError(ERRORS.OPTIONS_OBJECT_MISSING_PROPERTIES);
	}

	this.name = Strategy.NAME;
}

util.inherits(Strategy, passportStrategy.Strategy);

Strategy.prototype.authenticate = function(req, options) {
	logger.debug("authenticate", req.url, ", user :: ", req.user);
	options = options || {};

	// Handle possible error
	if (req.query && req.query.error) {
		logger.error(req.query.error);
		logger.error(req.query.error_description);
		return this.fail({ message: req.query.error_description });
	}

	// Handle oauth callback
	if (options.isOAuthCallback) {
		return retrieveAccessToken(req, this, options);
	}

	// Check for authentication
	if (req.user){
		logger.debug("Request already authenticated");
		return this.pass();
	}

	// Redirect to authorization endpoint
	logger.debug("Request not authenticated, redirecting to authorizationEndpoint");
	var redirectUrl = this.authorizationEndpoint;
	redirectUrl += "?response_type=authorization_code";
	redirectUrl += "&client_id=" + this.clientId;
	redirectUrl += "&redirect_uri=" + this.callbackUrl;
	req.session.originalUrl = req.url;
	this.redirect(redirectUrl);
}

function retrieveAccessToken(req, strategy, options){
	logger.debug("retrieveAccessToken");

	var formData = {
		grant_type: "authorization_code",
		client_id: strategy.clientId,
		redirect_uri: strategy.callbackUrl,
		code: req.query.code
	}

	request.post({
		url: strategy.tokenEndpoint,
		form: formData
	}, function (err, response, body){
		if (err){
			logger.error(err);
			return strategy.fail();
		}

		if (response && response.statusCode == 200 && body){
			logger.debug("Got tokens, parsing", body)
			var parsedBody = JSON.parse(body);
			req.session = req.session || {};
			req.session.accessToken = parsedBody.access_token;
			req.session.idToken = parsedBody.id_token;
			var idTokenComponents = parsedBody.id_token.split("."); // [header, payload, signature]
			var decodedIdentity= new Buffer(idTokenComponents[1],"base64").toString();
			req.securityContext = JSON.parse(decodedIdentity);
			req.session.securityContext = JSON.parse(decodedIdentity);
			return strategy.success(req.securityContext);
		}

		logger.error("Failed to get tokens", body);
		return strategy.fail();
	}).auth(strategy.clientId, strategy.secret);
}

Strategy.MCA_WEBSITE_STRATEGY = "mca-website-strategy";
Strategy.NAME = Strategy.MCA_WEBSITE_STRATEGY;
Strategy.MCA_LOGIN_URL = "/" + Strategy.MCA_WEBSITE_STRATEGY + "/oauth/login";
Strategy.setup = function (passport) {
	passport.serializeUser(function (user, done) {
		done(null, user || {});
	});

	passport.deserializeUser(function (user, done) {
		done(null, user);
	});
}

exports = module.exports = Strategy;