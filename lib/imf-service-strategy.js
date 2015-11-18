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


var MonitoringSDK = require('bms-monitoring-sdk-node');
var util = require('util');
var imfStrategy = require('./imf-strategy');
var FilterUtil = require('./util/filter-util');
var ibmlogger   = require('./util/security-logger');
function Strategy(options) {
	if (!process.env.imfServiceUrl) { 
		var msg = 'The environment variable "imfServiceUrl" is required.';
		ibmlogger.getLogger().error(msg);
		throw new TypeError(msg); 
	}
	this.analytics = MonitoringSDK('MobileSecurity', function errorHandler (err) {
		ibmlogger.getLogger().error('Failed to initialize MonitoringSDK.',err);
	});

	imfStrategy.Strategy.call(this,options);
	this.name = 'mca-service-strategy';
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, imfStrategy.Strategy);

Strategy.prototype.authenticate = function(req,options) {
	var appId = FilterUtil.getAppIdFromUrl(req.originalUrl);
	
	if (!appId) {
		var msg = 'Can\'t get valid application id from request url.';
		ibmlogger.getLogger().error(msg);
		this.fail(400);
	}
	
	if (!options) {
		options = {};
	}
	
	var authenticateOptions = FilterUtil.clone(options);
	authenticateOptions.appId = appId;
	authenticateOptions.serverUrl = process.env.imfServiceUrl;

	imfStrategy.authenticate(this,authenticateOptions,req);
}
	
exports = module.exports = Strategy;