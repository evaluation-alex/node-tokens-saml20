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
      , subject, subjectNameID, subjectConfirmation, subjectConfirmationData;
    
    assertion.c('saml:Issuer').t(issuer);
    
    
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
    
    
    console.log(assertion);
    console.log(assertion.toString());
    
    var sa = xmldsig.sign(assertion.toString());
    console.log(sa);
    
    cb(null, sa);
  }
}
