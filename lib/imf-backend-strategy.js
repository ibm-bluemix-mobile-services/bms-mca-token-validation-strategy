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
var userTokenSDK = require('imf-oauth-user-sdk');
var imfStrategy = require('./imf-strategy');
var FilterUtil = require('./util/filter-util');
var ibmlogger   = require('./util/security-logger');
var util = require('util');

function Strategy(options) {
	this.appId = FilterUtil.getApplicationIdFromVcap();
	this.serverUrl = FilterUtil.getServerUrlFromVcap();
	
	if (!this.appId) { 
		var msg = 'Can\'t get the application_id from VCAP_APPLICATION, please check if the application running on bluemix.'; 
		ibmlogger.getLogger().error(msg);
		throw new TypeError(msg);
	}
	
	if (!this.serverUrl) { 
		var msg = 'Can\'t get serverUrl from VCAP_SERVICES, please check if the application running on bluemix or bind with IBM MobileFirst Platform service.';
		ibmlogger.getLogger().error(msg);
		throw new TypeError(msg);
	}
	this.analytics = MonitoringSDK('MobileSecurity', function errorHandler (err) {
		ibmlogger.getLogger().error('Initialize the analytics instance failed.',err);
	},{
		AZFilterAppId: this.appId,
		AZServerUrl: this.serverUrl,
		AZTokenProvider: userTokenSDK.getAuthorizationHeader
	});
	imfStrategy.Strategy.call(this, options);
	this.name = 'mca-backend-strategy';
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, imfStrategy.Strategy);

Strategy.prototype.authenticate = function(req,options) {
	if (!options) {
		options = {};
	}
	
	var authenticateOptions = FilterUtil.clone(options);
	authenticateOptions.appId = this.appId;
	authenticateOptions.serverUrl = this.serverUrl;

	imfStrategy.authenticate(this,authenticateOptions,req);
}

exports = module.exports = Strategy;