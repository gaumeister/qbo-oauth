

var oauth1 = require('./oauth1');

/**
  @example <caption>sample usage</caption>
  var helper = require('@apigrate/qbo-oauth');

  var oauth1helper = new helper.QboOauth1('localhost/foo','abc','123');

  oauth1helper.getRequestToken()
  .then(function(result){
  	console.info("Result: "+JSON.stringify(result));
  })
  .catch(function(err){
  	console.error(err);
  });

*/
module.exports.QboOauth1 = oauth1;
