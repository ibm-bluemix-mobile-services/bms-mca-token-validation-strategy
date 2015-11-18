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
var RejectionMessage = require('./responses').RejectionMessage;
var ibmlogger   = require('./security-logger');
var CommonCache = require('./common-cache');
var TokenDecoder = require('./token-decoder');
var KeyReader = require('./key-reader.js');
var FilterUtil = require('./filter-util');
var AsyncQueue = require("./async-queue");
var Constant = require("../constant");
var fs = require('fs');
var _ = require('underscore');

const ACCESS_TOKEN_HEADER = "Authorization";
const AUTHORIZATION_BEARER = "Bearer";

var ImfTokenValidator = {};

ImfTokenValidator.validate = function(options,done) {
	var appId = options && options.appId;
	var serverUrl = options && options.serverUrl;
	var authorization = options && options.authorization;

	if (_.isUndefined(appId) || _.isNull(appId) || _.isEmpty(appId)) {
		ibmlogger.getLogger().error('Missing appId');
		return done(null,null,{status:401,validationCode:Constant.AUTHORIZATION_FAILED_MISSING_PARAMETER});
	}
	
	if (_.isUndefined(serverUrl) || _.isNull(serverUrl) || _.isEmpty(serverUrl)) {
		ibmlogger.getLogger().error('Missing serverUrl');
		return done(null,null,{status:401,validationCode:Constant.AUTHORIZATION_FAILED_MISSING_PARAMETER});
	}
	
	if (_.isUndefined(authorization) || _.isNull(authorization) || _.isEmpty(authorization)) {
		ibmlogger.getLogger().error('Missing authorization');
		return done(null,null,{status:401,validationCode:Constant.AUTHORIZATION_FAILED_MISSING_AUTH_HEADER});
	}

	//Remove all space in the left and right side of the authorization.
	//And use only one space to replace the multiple spaces between the authorization.
	var tokens = authorization.replace(/(^\s*)|(\s*$)/g,"").replace(/\s+/g," ").split(' ');
	if (tokens.length!=2 && tokens.length!=3 || tokens[0] != AUTHORIZATION_BEARER) {
		//return 400 error if missing access token, or id token.
		ibmlogger.getLogger().error('The authorization does not meet the format "Bearer <access token> [<id token>]');
		return done(null,null,{status:400,validationCode:Constant.AUTHORIZATION_FAILED_MISSING_TOKEN});
	}
	
	var accessToken = tokens[1];
	var idToken = tokens.length==3?tokens[2]:null;
	var securityContextKey = idToken?accessToken+' '+idToken:accessToken;

	var requiredScopeArray = FilterUtil.getArrayFromString(options.scope,',');
	//Retrieve the security context from the securityContextCache
	var securityContextHolder = this.securityContextCache.get(securityContextKey);
	if (securityContextHolder) {
		ibmlogger.getLogger().debug('Retrieve the security context from the cache.');
		var grantedScope = securityContextHolder.scope;
		if (! validateScope(grantedScope,requiredScopeArray)) {
			var scope = requiredScopeArray.join(' ');
			return done(null,null,{code:'insufficient_scope',scope:scope,validationCode:Constant.AUTHORIZATION_FAILED_INSUFFICIENT_SCOPE});
		}
		var securityContext = securityContextHolder.securityContext;
		
		//var user = securityContext['imf.user'];
		return done(null,securityContext);
	}
	else{
		ibmlogger.getLogger().debug('Not found the security context from the cache, do the token validation.');
		var accessTokenJson = null;
		var strategy = this;
		
		//Decode the access token if not found the security context from cache.
		decodeToken(appId,serverUrl,accessToken,strategy).then(function(decodedToken){
				accessTokenJson = decodedToken;
				if (idToken) {
					//decode the id token if not found in the decodedIdTokenCache
					var idTokenJson = strategy.decodedIdTokenCache.get(idToken);
					if (!idTokenJson) {
						return decodeToken(appId,serverUrl,idToken,strategy);
					}
					else{
						return Q.resolve(idTokenJson);
					}
				}
				else {
					return Q.resolve(null);
				}
			}
		)
		.then(function(idTokenJson){
				//add the decode id token in the cache and goto next filter.
				if (idTokenJson) {
					strategy.decodedIdTokenCache.set(securityContextKey,idTokenJson,idTokenJson.exp-Date.now()/1000);
				}
				var securityContextHolder = buildSecurityContext(strategy,securityContextKey,accessTokenJson,idTokenJson);
				var grantedScope = securityContextHolder.scope;
				if (! validateScope(grantedScope,requiredScopeArray)) {
					var scope = requiredScopeArray.join(' ');
					return done(null,null,{code:'insufficient_scope',scope:scope,validationCode:Constant.AUTHORIZATION_FAILED_INSUFFICIENT_SCOPE});
				}
					
				var securityContext = securityContextHolder.securityContext;
				//req.securityContext = securityContext;
				//var user = securityContext['imf.user'];

				return done(null,securityContext);
			}
		).catch(function(err){ 
			// assert may throw exception and if not catch it hangs
			ibmlogger.getLogger().error(err);
			
			//If the err is coming from the rejection message, the the token is invalid
			if (err instanceof RejectionMessage && err.code == RejectionMessage.INVALID_TOKEN_ERROR) {
				//the access token has been decoded successfully and the error is come from decoding id token
				var validationCode = Constant.AUTHORIZATION_FAILED_INVALID_ACCESS_TOKEN;
				if (accessTokenJson) {
					strategy.invalidTokenCache.set(idToken,idToken);
				}
				else {
					strategy.invalidTokenCache.set(accessToken,accessToken);
					validationCode = Constant.AUTHORIZATION_FAILED_INVALID_ID_TOKEN;
				}
				
				done(null,null,{code:'invalid_token',validationCode:validationCode});
				//parent.processErrorCode('invalid_token',res);
			}
			else {
				done(null,null,{status:500,validationCode:Constant.AUTHORIZATION_FAILED_INTERNAL_ERROR});
				//res.status(500).send('sorry, exception occurs during the validation.');
			}
        });
	}

}

function decodeToken(appId,serverUrl,token,strategy) {
	
	//check the token in the invalid token cache, if exists, output with invalid_token error
	if(strategy.invalidTokenCache.get(token)) {
		ibmlogger.getLogger().debug('The token',token,'is found in the invalid token cache. Response with 401 error.');
		//this.processErrorCode('invalid_token',res);
		return Q.reject(RejectionMessage("The requested token is invalid","The requested token is existed in invalid token cache, reject it directly.", RejectionMessage.INVALID_TOKEN_ERROR));
	}
	
    var payload={
			oauth_provider: 'worklight',
			access_token: token
	};
	
	payload.applicationId = appId;
	ibmlogger.getLogger().debug('decode token for appid',appId);

	var pubkey = strategy.publicKeyCache.get(appId);//strategy.publicKeyData[appId] && strategy.publicKeyData[appId].pubkey;
    if (pubkey) {
    	ibmlogger.getLogger().debug('get public key from cache, decode the token with the key directly.');
    	
    	payload.appkey = pubkey;
    	return TokenDecoder.decode(payload);
    }
    else {
    	ibmlogger.getLogger().debug('public key is not existed in cache for appid',appId, 'trying to get it.');
    	//The first time to access the public key for appid.
    	if (! strategy.publicKeyCache.hasKey(appId)) {
    		//set flag to indicate the public key for appid is retrieving
    		strategy.publicKeyCache.set(appId,null,60);
    		ibmlogger.getLogger().debug('first time to request public key for appid ',appId);

        	return KeyReader.getPublicKey(appId,serverUrl).then(function(pubkey){
        		ibmlogger.getLogger().debug('The public key is arrived for appid:',appId,'emit the event to notify its queue to release the requests for decoding token.');
        		payload.appkey = pubkey;

        		//cache the public key for appid
        		strategy.publicKeyCache.set(appId,pubkey,600);
        		strategy.queue.emit('resolve',appId);
        		return TokenDecoder.decode(payload);
        	});
    	}
    	else {
    		ibmlogger.getLogger().debug('The public key is requested, and has not got it yet, add the token decode request in queue for appid:',appId);
    		//add the payload into queue until the key is retrieved
        	return strategy.queue.add(appId,payload).then(function(p){
        		p.appkey = strategy.publicKeyCache.get(appId);//publicKeyData[appId].pubkey;
        		return TokenDecoder.decode(p);
        	})
    	}
    } 
}

function validateScope(grantedScope, requiredScopeArray) {
	var validated = true;
	/*
	var nowUtc = Date.now();
	
	if (grantedScope) {
		for(var scopeName in grantedScope) {
			var scope = grantedScope[scopeName];
			if (scope && scope.exp && scope.exp<nowUtc/1000) {
				//mandatory scope should not be expired
				if (scope.mandatory) {
					validated = false;
					break;
				}
					
				if (requiredScopeArray.indexOf(scopeName)>=0) {
					validated = false;
					break;
				}
			}
		}
	}
	
	//the granted scope is empty or is not contained in the required scopes
	requiredScopeArray.forEach(function(scopeName){
		if (!grantedScope || !grantedScope[scopeName]) {
			validated = false;
		}
	});
	*/
	return validated;
}

function buildSecurityContext(strategy,securityContextKey,accessTokenJson,idTokenJson) {
	var securityContext = {};
    var nowUtc = Date.now()/1000;
    var expUtc = accessTokenJson.exp;

    var scope = '';
    var imfScope = null;
    if (accessTokenJson.hasOwnProperty('imf.scope')) {
    	imfScope = accessTokenJson['imf.scope'];
    	for(var scopeName in imfScope) {
    		if (scope == '') {
    			scope = scopeName;
    		}
    		else {
    			scope = scope+','+scopeName;
    		}
    	}
    }
    
	//var clientId = accessTokenJson['prn'];
	//var issuer = accessTokenJson['iss'];
	//var anonymouseUserName = clientId+':'+issuer;
	
    if (idTokenJson) {
    	securityContext['imf.sub'] = idTokenJson['sub'];
    		
    	if (idTokenJson.hasOwnProperty('imf.user')) {
    		securityContext['imf.user'] = idTokenJson['imf.user'];
    	}
    	else {
    		securityContext['imf.user'] = {};
    	}
        
        securityContext['imf.device'] = idTokenJson['imf.device'];
        securityContext['imf.application'] = idTokenJson['imf.application'];
    }
    else {
    	//var uniqueId = accessTokenJson
    	securityContext['imf.sub'] = accessTokenJson['prn'];
    	securityContext['imf.user'] = {};
    	securityContext['imf.device'] = {};
    	securityContext['imf.application'] = {};
    }

    var securityContextHolder = {securityContext:securityContext, scope:imfScope};
    //add the securityContext for the valid token, with ttl same with the expiration seconds.
    strategy.securityContextCache.set(securityContextKey,securityContextHolder,expUtc-nowUtc);
   
    return securityContextHolder;
}

exports = module.exports = ImfTokenValidator;