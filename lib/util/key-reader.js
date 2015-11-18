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
var base64url = require('base64url');
var request = require('request');
var getPem = require('rsa-pem-from-mod-exp');
var ibmlogger   = require('./security-logger');
var CommonCache = require('./common-cache');
var FilterUtil = require('./filter-util');
var RejectionMessage = require("./responses").RejectionMessage;

const PUBLIC_KEY_PATH = "authorization/v1/apps/{appId}/publickey",
	  BROKER_AUTHORIZATION_CACHE_KEY = 'Authorization';

var uaaTokenCache = new CommonCache(1);

var KeyReader = {};

KeyReader.getPublicKey = function(appId,imfServiceUrl) {	
	var requestUrl = imfServiceUrl;
	if (requestUrl[requestUrl.length-1]!='/') {
		requestUrl += '/';
	}
	
	requestUrl = requestUrl+PUBLIC_KEY_PATH.replace('{appId}',appId);
	return getPublicKeyFromUrl(requestUrl);
}

function getPublicKeyFromUrl(requestUrl) {
//function keyReader(authorizationServerUrl) {
	var deferred = Q.defer();
	
	request(requestUrl, {rejectUnauthorized: false,requestCert: true},function (error, response, body) {
		if (error || response.statusCode != 200) {
			var info = error?"["+error+"]":"["+response.statusCode+":"+body+"] Access public key url '"+requestUrl+"' failed.";
			ibmlogger.getLogger().error(info);
			return deferred.reject(RejectionMessage("Failed to retrieve public key", info, RejectionMessage.PUBLICK_KEY_ERROR));
		}
		else {
			  var keyJson = FilterUtil.getJson(body);
			  var pem = getPem(keyJson.n,keyJson.e);
			  return deferred.resolve(pem);
		}
	});
	return deferred.promise;
}

exports = module.exports = KeyReader;