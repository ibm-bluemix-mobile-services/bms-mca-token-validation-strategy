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
var packageVersion = require('./../package.json').version;
console.log("bms-mca-token-validation-strategy initialized :: v" + packageVersion);

// Used to protect services.
var MCAServiceStrategy = require('./imf-service-strategy');

// Used to protect backends. Checks Authorization header in incoming requests and validates it using MCA public certificate
var MCABackendStrategy = require('./imf-backend-strategy');

// Used to protect resources.
var MCAResourceStrategy = require('./imf-resource-strategy');

// Used to protect websites. Implements OAuth2 Authorization Code flow
var MCAWebSiteStrategy = require('./mca-website-strategy');
/** 
 * Expose `Strategy` directly from package.
 */
//exports = module.exports = Strategy;

/**
 * Export constructors.
 */
exports = module.exports = {
	MCAServiceStrategy: MCAServiceStrategy,
	MCABackendStrategy: MCABackendStrategy,
	MCAResourceStrategy: MCAResourceStrategy,
	MCAWebSiteStrategy: MCAWebSiteStrategy
}

