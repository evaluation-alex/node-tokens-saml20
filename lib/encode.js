var $ = require('xtraverse'),
    xmldsig = require('xmldsig'),
    moment = require('moment');


module.exports = function(options) {
  options = options || {};
  
  var issuer = options.issuer
    , key = options.key
    , kid = options.kid
    , algorithm = options.algorithm || 'RS256';
  
  if (!issuer) { throw new TypeError('SAML 2.0 assertion encoder requires an issuer'); }
  if (!key) { throw new TypeError('SAML 2.0 assertion encoder requires a key'); }
  
  return function saml2(info, cb) {
    var assertion = $('<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"/>')
      , subject, subjectNameID, subjectConfirmation, subjectConfirmationData
      , conditions
      , authnStatement, authnContext;
    
    assertion.c('saml:Issuer').t(issuer);
    
    
    // <saml:Subject/>
    subject = assertion.c('saml:Subject');
    
    subjectNameID = subject.c('saml:NameID').t(info.subject).up();
    switch (info.subjectIdentiferFormat) {
    case 'persistent':
    case 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent':
    default:
      subjectNameID.attr('Format', 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent');
      break;
    }
    
    subjectConfirmation = subject.c('saml:SubjectConfirmation');
    switch (info.subjectConfirmationMethod) {
    case 'bearer':
    case 'urn:oasis:names:tc:SAML:2.0:cm:bearer':
    default:
      subjectConfirmation.attr('Method', 'urn:oasis:names:tc:SAML:2.0:cm:bearer');
      subjectConfirmationData = subjectConfirmation.c('saml:SubjectConfirmationData');
      if (info.recipient) { subjectConfirmationData.attr('Recipient', info.recipient); }
      if (info.inResponseTo) { subjectConfirmationData.attr('InResponseTo', info.inResponseTo); }
      if (info.expiresAt) { subjectConfirmationData.attr('NotOnOrAfter', moment(info.expiresAt).utc().format('YYYY-MM-DDTHH:mm:ss') + 'Z'); }
      break;
    }
    
    // <saml:Conditions/>
    conditions = assertion.c('saml:Conditions');
    if (info.notBefore) { subjectConfirmationData.attr('NotBefore', moment(info.notBefore).utc().format('YYYY-MM-DDTHH:mm:ss') + 'Z'); }
    if (info.expiresAt) { subjectConfirmationData.attr('NotOnOrAfter', moment(info.expiresAt).utc().format('YYYY-MM-DDTHH:mm:ss') + 'Z'); }
    if (Array.isArray(info.audience)) {
      // TODO:
    } else {
      conditions.c('saml:AudienceRestriction').c('saml:Audience').t(info.audience);
    }
    
    // <saml:AuthnStatement/>
    if (info.authenticatedAt) {
      authnStatement = assertion.c('saml:AuthnStatement', { AuthnInstant: moment(info.authenticatedAt).utc().format('YYYY-MM-DDTHH:mm:ss') + 'Z' });
      authnContext = authnStatement.c('saml:AuthnContext')
      if (!info.authenticationContextClassReference) {
        authnContext.c('saml:AuthnContextClassRef').t('urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified');
      } else {
        // TODO
      }
    }
    
    // TODO: 
    
    
    console.log(assertion);
    console.log(assertion.toString());
    
    var sa = xmldsig.sign(assertion.toString());
    console.log(sa);
    
    cb(null, sa);
  }
}
