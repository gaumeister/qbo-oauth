var _ = require('lodash');
var request = require('request');
var uuid = require('uuid');
var moment = require('moment');
var CryptoJS = require("crypto-js");
var Q = require('q');
var qs = require('querystring');
var xml2js = require('xml2js');

const INTUIT_REQUEST_TOKEN_URL = 'https://oauth.intuit.com/oauth/v1/get_request_token';
const INTUIT_ACCESS_TOKEN_URL = 'https://oauth.intuit.com/oauth/v1/get_access_token';
const INTUIT_USER_AUTHORIZATION_URL = 'https://appcenter.intuit.com/Connect/Begin';
const INTUIT_RECONNECT_URL = 'https://appcenter.intuit.com/api/v1/connection/reconnect';
const INTUIT_DISCONNECT_URL = 'https://appcenter.intuit.com/api/v1/connection/disconnect';

var LOGGER = null;
/**

  Provides functionality to negotiate OAuth 1.0a flow for getting an Access token
  from Intuit for QuickBooks Online API access.
  @param oauthCallbackUrl the url to which the application will be redirected upon conclusion
    of the oauth call. This URL will the following query parameters: 1. oauth_token - the actual oauth token,
    2. oauth_verifier - the verifier, 3. realmId - the quickbooks online company id.
  @param oauthConsumerKey issued to you, the application developer, for your app
  @param oauthConsumerSecret issued to you, the application developer, for your app
  @param logger an optional winston-compatible logger.

  @example <caption>How used</caption>
    var helper = QboAuthHelper("http://localhost:3100/qbo/receive-verification",
      "qyprdCWrJtfoNviKGC8woJ2d7fHJk0",
      "ajEZOsmF1dmpA7PkMYKOBVIDFpkIktovHsjFgAsx");
    helper.
  @version 1.0.1
*/
function QboAuthHelper(oauthCallbackUrl, oauthConsumerKey, oauthConsumerSecret, logger){
  this.oauthCallbackUrl = oauthCallbackUrl;
  this.oauthConsumerKey = oauthConsumerKey;
  this.oauthConsumerSecret = oauthConsumerSecret;
  if(!_.isNil(logger)){
    LOGGER = logger;
  } else{
    LOGGER = { error: console.error, warn: console.error, info: console.log, debug: console.log, silly: console.log };
  }
}
/**
  First leg of Intuit OAuth 1.0 flow. Gets a request token that
  will be used in the last leg to retrieve an access token.

  @return {object} a promise bearing an object containing the token information
  needed for the next leg. Typically, you will stash the oauth_token_secret into
  temporary storage (i.e. cookie, session etc), and the redirect the user to
  the user_authorization_url, where they will provide credentials directly to
  Intuit. Intuit will then redirect back to oauthCallbackUrl (specified in
  constructor), which can then be used to swap the data returned from the
  authentication for an actual access token (that is used for API access).
  @example <caption>Sample object</caption>
  {
    oauth_token_secret: 'oVCZXuvhMJZQyGCTxkAekiIhJBssBRJ5xzoCL00F',
    oauth_token: 'qyprdzEisEBkS4nahL16mPSjBZ2HsSs2wxvry5lpSQwbCNm7',
    oauth_callback_confirmed: 'true',
    user_authorization_url: 'https://appcenter.intuit.com/Connect/Begin?oauth_token=qyprdzEisEBkS4nahL16mPSjBZ2HsSs2wxvry5lpSQwbCNm7'
  }
*/
QboAuthHelper.prototype.getRequestToken = function(){
  var self = this;

  return Q.Promise(function(resolve, reject){

    var requestTokenUrl = self.createRequestTokenUrl();

    request.get( requestTokenUrl, function(err, resp, body){
      if(err){
        reject(err);
      } else {
        if(resp.statusCode!==200){
          reject('Request was invalid (HTTP '+resp.statusCode+').\n' + body);
          return;

        } else {
          var parsedData = qs.parse(body)

          //For convenience, built the user auth url
          var userAuthorizationUrl = INTUIT_USER_AUTHORIZATION_URL + '?oauth_token=' + parsedData.oauth_token;
          parsedData.user_authorization_url = userAuthorizationUrl;

          LOGGER.debug('Received temporary request token. ')
          LOGGER.debug(JSON.stringify(parsedData));
          resolve( parsedData );
          return;
        }
      }
    });
  });

};


/**
  Issues the request for an access token. This function should be called once a user
  has authorized and received a token secret.
*/
QboAuthHelper.prototype.getAccessToken = function(oauthToken, oauthTokenSecret, oauthVerifier){
  var self = this;
  return Q.Promise(function(resolve, reject){

    var accessTokenUrl = self.createAccessTokenUrl(oauthTokenSecret, oauthToken, oauthVerifier);

    request.get( accessTokenUrl, function(err, resp, body){
      if(err){
        reject(err);
      } else {
        if(resp.statusCode!==200){
          reject('Request was invalid ('+resp.statusCode+').\n' + body);
        } else {
          var parsedData = qs.parse(body)
          parsedData.expires = moment().utc().add(180, 'days').toISOString();
          LOGGER.debug('Received accessToken. ');
          LOGGER.debug(JSON.stringify(parsedData));
          resolve( parsedData );
        }
      }
    });
  });

};

/**
  Issues a 'reconnection' request for a new access token. This obtains another
  access token that is valid for an additional 180 days. However, this renewal
  request can only be issued within 30 days of the currently granted access
  token's expiry, otherwise an error is issued.
  @return a promise bearing the renewal response.
*/
QboAuthHelper.prototype.getRenewedAccessToken = function(oauthToken, oauthTokenSecret){
  var self = this;
  return Q.Promise(function(resolve, reject){

    var oauth = {
      consumer_key: self.oauthConsumerKey,
      consumer_secret: self.oauthConsumerSecret,
      token: oauthToken,
      token_secret: oauthTokenSecret
    };

    request.get({
      url: INTUIT_RECONNECT_URL,
      oauth: oauth,
      qs: ''
    }, function(err, resp, body){
      if(err){
        reject(err)
      } else {
        //Got a response, but it is in XML and needs to be parsed.
        xml2js.parseString(body, {trim: true}, function(err2, result){
          if(err2){
            reject(err2);
          } else {
            if(result.ReconnectResponse.errorCode!=0){
              reject( new Error(result.ReconnectResponse.errorMessage) );
            } else {
              var ret = {
                oauth_token_secret: result.ReconnectResponse.OAuthTokenSecret,
                oauth_token: result.ReconnectResponse.OAuthToken,
                expires: moment().utc().add(180, 'days').toISOString()
              };
              resolve(ret);
            }
          }

        });//the xml parse
      }
    });//the request
  });//the promise
};

/**
  Invalidates an existing access token.
  @return a promise bearing a simple object of the form:
  <code>{ disconnected: boolean}</code> when the disconnection succeeds.
*/
QboAuthHelper.prototype.disconnect = function(oauthToken, oauthTokenSecret){
  var self = this;
  return Q.Promise(function(resolve, reject){

    var oauth = {
      consumer_key: self.oauthConsumerKey,
      consumer_secret: self.oauthConsumerSecret,
      token: oauthToken,
      token_secret: oauthTokenSecret
    };

    // var url = createDisconnectUrl(oauthToken);
    LOGGER.debug('Disconnect requested to: ' + INTUIT_DISCONNECT_URL);

    request.get({
      url: INTUIT_DISCONNECT_URL,
      oauth: oauth,
      qs: ''
    }, function(err, resp, body){
      LOGGER.debug('Disconnect result: \n' + JSON.stringify(body, null, 2));
      if(err){
        reject(err)
      } else {
        //Got a response, but it is in XML and needs to be parsed.
        xml2js.parseString(body, {trim: true}, function(err2, result){
          if(err2){
            reject(err2);
          } else {
            if(result.PlatformResponse.ErrorCode!=0){
              reject( new Error(result.PlatformResponse.ErrorMessage) );
            } else {
              resolve({ disconnected: true });
            }
          }

        });//the xml parse
      }
    });//the request
  });//the promise
};

/**
  Builds a signed REQUEST TOKEN URL for request token retrieval.
  @return the signed url based on the OAuth 1.0a parameters.
*/
QboAuthHelper.prototype.createRequestTokenUrl = function(){
  var url = INTUIT_REQUEST_TOKEN_URL;

  var parms = {
    'oauth_callback' : this.oauthCallbackUrl,
    'oauth_consumer_key' : this.oauthConsumerKey,
    'oauth_nonce' : uuid(),
    'oauth_signature_method' : 'HMAC-SHA1',
    'oauth_timestamp' : moment().format('X'),
    'oauth_version' : '1.0'
  };

  var url = buildUrl(INTUIT_REQUEST_TOKEN_URL, parms);

  //Add the signature parm.
  var sig = this.generateSignature('GET', INTUIT_REQUEST_TOKEN_URL, parms );

  url += '&oauth_signature=' + encodeURIComponent(sig);

  return url;
}

/**
  Builds a signed ACCESS TOKEN URL for access token retrieval.
  @return the signed url based on the OAuth 1.0a parameters.
*/
QboAuthHelper.prototype.createAccessTokenUrl = function(tokenSecret, oauthToken, oauthVerifier){
  var url = INTUIT_ACCESS_TOKEN_URL;

  var parms = {
    'oauth_callback' : this.oauthCallbackUrl,
    'oauth_consumer_key' : this.oauthConsumerKey,
    'oauth_nonce' : uuid(),
    'oauth_signature_method' : 'HMAC-SHA1',
    'oauth_timestamp' : moment().format('X'),
    'oauth_version' : '1.0',
    'oauth_token' : oauthToken,
    'oauth_verifier' : oauthVerifier
  };

  var url = buildUrl(INTUIT_ACCESS_TOKEN_URL, parms);

  //Add the signature parm.
  var sig = this.generateSignature('GET', INTUIT_ACCESS_TOKEN_URL, parms, tokenSecret );

  url += '&oauth_signature=' + encodeURIComponent(sig);

  return url;
}

QboAuthHelper.prototype.createDisconnectUrl = function(oauthToken){
  var parms = {
    'oauth_callback' : this.oauthCallbackUrl,
    'oauth_consumer_key' : this.oauthConsumerKey,
    'oauth_nonce' : uuid(),
    'oauth_signature_method' : 'HMAC-SHA1',
    'oauth_timestamp' : moment().format('X'),
    'oauth_version' : '1.0',
    'oauth_token' : oauthToken
  };

  var url = buildUrl(INTUIT_DISCONNECT_URL, parms);

  //Add the signature parm.
  var sig = this.generateSignature('GET', INTUIT_DISCONNECT_URL, parms );

  url += '&oauth_signature=' + encodeURIComponent(sig);

  return url;
}

/**
  Generates a HMAC-SHA1 request signature for signing a request.
*/
QboAuthHelper.prototype.generateSignature = function(method, url, paramsHash, tokenSecret){
  var sigBase = method.toUpperCase();
  sigBase += '&';
  sigBase += encodeURIComponent(url);
  sigBase += '&';
  var parmString = '';
  var parms = sortObject(paramsHash);
  _.each(parms, function(v,k){
    if(parmString===''){
      parmString+='' + k;//note not ? and not &
    } else {
      parmString+='&' + k;
    }
    parmString+='=' + encodeURIComponent(v);
  });
  LOGGER.debug('Unencoded Parm String is: ' + parmString );

  sigBase += encodeURIComponent(parmString);
  LOGGER.debug('Signature Base is: ' + sigBase );

  if(!tokenSecret) tokenSecret='';
  var signingKey = this.oauthConsumerSecret + '&' + tokenSecret;
  LOGGER.debug('Signing Key is: ' + signingKey );

  var hash = CryptoJS.HmacSHA1(sigBase, signingKey);
  LOGGER.debug('Hash is: ' + hash );

  var sig = hash.toString(CryptoJS.enc.Base64)
  LOGGER.debug('Signature is: ' + sig );
  return sig;
}

/**
  Convenience function for building a URL.
*/
function buildUrl(urlBase, parms){
  var p2 = sortObject(parms);
  var parmString = '';
  _.each(p2, function(v,k){
    if(parmString===''){
      parmString+='?' + k;
    } else {
      parmString+='&' + k;
    }
    parmString+='=' + encodeURIComponent(v);
  });
  return urlBase+parmString;
}

/**
  Given an object, sorts its keys in alphabetical order (important for
  the signature generation process).
*/
function sortObject(o) {
  return Object.keys(o).sort().reduce((r, k) => (r[k] = o[k], r), {});
}


module.exports=QboAuthHelper;
