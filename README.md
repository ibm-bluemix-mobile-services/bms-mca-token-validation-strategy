IBM Bluemix Mobile Services - Mobile Client Access Passport Strategies
===
Mobile Client Access service allows to protect your backend applications with a mobile enabled OAuth security.

The bms-mca-token-validation-strategy module provides the passport strategy and verification method to validate the access token and id token issues by a Mobile Client Access.

## Strategies
### MCABackendStrategy
```
passport.use(new MCABackendStrategy(options));
```

The `options` parameter is optional.  If specified, it can contain:

* `cacheSize` The cache size, the default value is 10000;

The MCABackendStrategy is used for a backend application that is deployed on IBM Bluemix. It will validate the `authorization` header from an incoming request against the MCA server url specified in the VCAP_SERVICES variable, where the service name starts with `AppID`, for the `appId` extracted from VCAP_APPLICATION.

### MCAResourceStrategy
```
passport.use(new MCAResourceStrategy(options));
```

The `options` parameter is optional.  If specified, it can contain:

* `appId` Optional. Specifies the application id for which the authorization will be validated.
* `applicationIdProvider` Optional. Specifies a mechanism to obtain the application id by calling the function applicationIdProvider(request). The MCAResourceStrategy will try to get the application id from the options appId first, then by calling the method applicationIdProvider; if neither of these options are specified, the application id will be obtained from the request url.
* `serverUrl` Specifies the IBM MobileFirst server URL from which the public key will be retrieved to verify the authorization header.
* `cacheSize` The cache size, the default value is 10000.

Instead of defining the above optional `appId`,`applicationIdProvider` or `serverUrl` in the options parameter of the MCAResourceStrategy constructor, you can also specify them in the options of the passport.authenticate() method. No matter where these three options are specified, the application id and serverUrl are mandatory, otherwise an error 400 will occur.

## Sample
The following sample code shows how to use MCABackendStrategy in a Node.js application:


Start by making sure that you have installed all the required modules 

```
$ npm install -save express
$ npm install -save passport
$ npm install -save bms-mca-token-validation-strategy
```

Add the below code to your Node.js application

```
var express = require('express');
var passport = require('passport');
var MCABackendStrategy = require('bms-mca-token-validation-strategy').MCABackendStrategy;

passport.use(new MCABackendStrategy());

var app = express();
app.use(passport.initialize());

app.get('/v1/apps/:appid/service', passport.authenticate('mca-backend-strategy', {session: false }),
	function(req, res){
		res.send(200, "Success!");
	}
);

app.listen(3000);
```


## Authorization header
The authorization header in the request consist of three parts `Bearer`, `Access Token` and `Id Token` that are separated by a white space:
`Bearer <Access Token> <Id Token>`

For bms-mca-token-validation-strategy, ``<Access Token>`` is mandatory and ``<Id Token>`` is optional.
The validation works as follows:
* It will verify the signature of the access token and id token, as well as their exp field.
* It requires that aud be the same as the application id for which the authorization is validated.
* It requires that the authorization header start with Bearer, otherwise a 400 error will be returned, with the response header `WWW-Authenticate: Bearer realm="imfAuthentication"`.
* If the access token or id token is invalid, for example, they have expired or cannot be decodes, validation will return a 401 error, with the response header `WWW-Authenticate: Bearer realm="imfAuthentication", error="invalid_token"`.

## Mobile Client Access security context
After the authorization validation has passed, a security context object is added in the current request object. You can get a reference to it by calling `request.securityContenxt` The security context contains the subject, user, device and the application information stored in the below fields:

* `imf.sub` The subject of the id token or the unique id of the client if there is no id token.
* `imf.user` The user identity extracted from the id token. If there is no id token, this field holds a blank object.
* `imf.device` The device identity extracted from the id token. If there is no id token, this field holds a blank object.
* `imf.application` The application identity extracted from the id token. If there is no id token, this field holds a blank object.

The imf.user field in the security context is extracted as the user object in passport framework. See sample below

```
app.get('/v1/apps/:appid/service', passport.authenticate('mca-backend-strategy', {session: false }),
	function(req, res){
		res.send(200, req.securityContext);
	}
);
```
The above code would return

```

{ 
	"imf.sub":"myclientid",
	"imf.user": {
		"id":"user-name",
		"authBy":"myrealm",
		"displayName":"display-name"
	},
	"imf.device": {
		"id":"device-id",
		"platform":"iOSnative",
		"model":"device-model",
		"osVersion":"device-os"
	},
	"imf.application": {
		"id":"ios.bundle.id",
		"version":"1.0"
	}
}
```

## License
This package contains sample code provided in source code form. The samples are licensed under the under the Apache License, Version 2.0 (the "License").  You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0 and may also view the license in the license.txt file within this package.  Also see the notices.txt file within this package for additional notices.
