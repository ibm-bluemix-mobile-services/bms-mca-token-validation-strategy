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

var imfStrategy = require('./imf-strategy'),
	FilterUtil = require('./util/filter-util'),
	ibmlogger   = require('./util/security-logger'),
	util = require('util');

function Strategy(options) {
	this.appId = options && options.appId;
	this.applicationIdProvider = options && options.applicationIdProvider;
	this.serverUrl = options && options.serverUrl;

	if (!this.appId && this.applicationIdProvider && typeof this.applicationIdProvider != 'function') {
		var msg = 'The option "applicationIdProvider" should be a function.';
		ibmlogger.getLogger().error(msg);
		throw new TypeError(msg); 
	}
	
	imfStrategy.Strategy.call(this,options);
	this.name = 'mca-resource-strategy';
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, imfStrategy.Strategy);

Strategy.prototype.authenticate = function(req,options) {
	var appId = options && options.appId || this.appId;
	var applicationIdProvider = options && options.applicationIdProvider || this.applicationIdProvider;
	var serverUrl = options && options.serverUrl || this.serverUrl;
	
	appId = appId || applicationIdProvider && applicationIdProvider(req) || FilterUtil.getAppIdFromUrl(req.originalUrl);
	
	if (!appId) {
		var msg = 'Can\'t get application id from options.appId, applicationIdProvider or request.';
		ibmlogger.getLogger().error(msg);
		return this.fail(400);
	}
	
	if (!serverUrl) {
		var msg = 'The option "serverUrl" is required.';
		ibmlogger.getLogger().error(msg);
		return this.fail(400);
	}

	if (!options) {
		options = {};
	}
	var authenticateOptions = FilterUtil.clone(options);
	authenticateOptions.appId = appId;
	authenticateOptions.serverUrl = serverUrl;
	
	imfStrategy.authenticate(this,authenticateOptions,req);
}

exports = module.exports = Strategy;