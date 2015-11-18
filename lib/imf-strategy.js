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
var Q = require('q');
var RejectionMessage = require('./util/responses').RejectionMessage;
var ibmlogger   = require('./util/security-logger');
var CommonCache = require('./util/common-cache');
var	AsyncQueue = require("./util/async-queue");
var ImfTokenValidator = require("./util/imf-token-validator");
var Constant = require("./constant");
var _ = require('underscore');
var passport = require('passport-strategy');
var util = require('util');

var ImfStrategy = {};

ImfStrategy.Strategy = function(options) {

	//if (!verify) { throw new TypeError('ImfStrategy requires a verify callback'); }
	
	passport.Strategy.call(this);
	this.name = 'imf-token';
	this._verify = ImfTokenValidator.validate;
	this._realm = 'imfAuthentication';
	
	this.cacheSize = options && options.cacheSize||10000;
	
	//If not specify the imfServiceUrl then using the default value.
	//this.imfServiceUrl = FilterUtil.getEnvProperty('imfServiceUrl') || 'http://imf-multitenant-dev.stage1.mybluemix.net/mfp';
	
	this.invalidTokenCache = new CommonCache(this.cacheSize);
	this.securityContextCache = new CommonCache(this.cacheSize);
	this.decodedIdTokenCache = new CommonCache(this.cacheSize);
	this.publicKeyCache = new CommonCache(this.cacheSize);
	//this.publicKeyData = {};
	this.queue = new AsyncQueue();
	
	if (options && options.logger) {
		ibmlogger.setLogger(options.logger);
	}
	
	return this;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(ImfStrategy.Strategy, passport.Strategy);

ImfStrategy.authenticate = function(strategy,options,req) {

	var authorization;
	if (req.headers && req.headers.authorization) {
		authorization = req.headers.authorization;
	}
	options.authorization = authorization;
	
	function verified(err, securityContext, info) {
		if (strategy.analytics) {
			var map = getAnalyticsMapper();
			var validationCode = info?info.validationCode:Constant.AUTHORIZATION_SUCCESS;
			validationCode = map[validationCode];
			
			//the securityContext has value, represents validation successfully. Otherwise, failed.
			var timeNow = new Date().getTime/1000;
			var event = {
				timestamp: timeNow,
				appId: options.appId,
				clientId : req && req.headers && req.headers[Constant.CLIENT_ID],
				deviceAppName : securityContext && securityContext[Constant.IMF_APPLICATION] && securityContext[Constant.IMF_APPLICATION].id,
				deviceAppVersion : securityContext && securityContext[Constant.IMF_APPLICATION] && securityContext[Constant.IMF_APPLICATION].version,
				deviceId : securityContext && securityContext[Constant.IMF_DEVICE] && securityContext[Constant.IMF_DEVICE].id,
				deviceModel : securityContext && securityContext[Constant.IMF_DEVICE] && securityContext[Constant.IMF_DEVICE].model,
				deviceOS : securityContext && securityContext[Constant.IMF_DEVICE] && securityContext[Constant.IMF_DEVICE].platform,
				deviceOSVersion : securityContext && securityContext[Constant.IMF_DEVICE] && securityContext[Constant.IMF_DEVICE].osVersion,
				globalTrackingId: req && req.headers && req.headers[Constant.TRACKING_ID_HEADER],
				origin: Constant.ORIGIN,
				resourceUrl: req && req.originalUrl,
				success: securityContext?true:false,
				validationCode: validationCode
			};
			
			try{
				strategy.analytics.reportEvent(Constant.MobileSecurityValidation,event);
			}catch(error) {
				ibmlogger.getLogger().error('Sending analytics event error',event,error);
			}
		}
		if (err) { return strategy.error(err); }
		if (!securityContext) {
			info = info || {code:'invalid_token',status:401};
			//console.dir(info);
			return strategy.fail(getChallenge(strategy._realm,info.code,info.scope),info.status);
		}
		req.securityContext = securityContext;
		var user = securityContext['imf.user'];
		strategy.success(user, null);
	}

	strategy._verify(options,verified);
};

function getAnalyticsMapper() {
	var map = [];

	map[Constant.AUTHORIZATION_FAILED_MISSING_PARAMETER] = Constant.AUTHORIZATION_FAILED_MISSING_PARAMETER;
	map[Constant.AUTHORIZATION_FAILED_MISSING_AUTH_HEADER] = Constant.AUTHORIZATION_FAILED_MISSING_AUTH_HEADER;
	map[Constant.AUTHORIZATION_FAILED_MISSING_TOKEN] = Constant.AUTHORIZATION_FAILED_MISSING_TOKEN;
	map[Constant.AUTHORIZATION_FAILED_INVALID_ACCESS_TOKEN] = Constant.AUTHORIZATION_FAILED_INVALID_ACCESS_TOKEN
	map[Constant.AUTHORIZATION_FAILED_INVALID_ID_TOKEN] = Constant.AUTHORIZATION_FAILED_INVALID_ID_TOKEN;
	map[Constant.AUTHORIZATION_FAILED_INTERNAL_ERROR] = Constant.AUTHORIZATION_FAILED_INTERNAL_SERVER_ERROR;
	map[Constant.AUTHORIZATION_SUCCESS] = Constant.AUTHORIZATION_SUCCESS;
	return map;
};

function getChallenge(realm,errCode,scope) {
	var challenge = 'Bearer realm="' + realm + '"';
	if (errCode) {
		challenge += ', error="' + errCode + '"';
	}
	if (scope) {
		challenge += ', scope="' + scope + '"';
	}
	
	return challenge;
};

exports = module.exports = ImfStrategy;