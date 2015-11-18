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
console.log("bms-mca-token-validation-strategy initialized :: v" + process.env.npm_package_version);

var ImfServiceStrategy = require('./imf-service-strategy');
var ImfBackendStrategy = require('./imf-backend-strategy');
var ImfResourceStrategy = require('./imf-resource-strategy');
/** 
 * Expose `Strategy` directly from package.
 */
//exports = module.exports = Strategy;

/**
 * Export constructors.
 */
exports = module.exports = {
		MCAServiceStrategy: ImfServiceStrategy,
		MCABackendStrategy: ImfBackendStrategy,
		MCAResourceStrategy: ImfResourceStrategy
}

