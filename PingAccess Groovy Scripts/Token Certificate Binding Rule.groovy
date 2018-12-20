import java.security.MessageDigest
exc?.log.info "*** TokenCertificateBinding start"
exc?.log.info "TokenCertificateBinding Mutual TLS Certificate Bound Access Token Groovy Rule"
if (exc?.response == null) // only do this when processing the inbound request and not after the site has been called
{
  exc?.log.info "TokenCertificateBinding in request flow (IF:1)"
  if (exc?.sslData != null) {
    exc?.log.info "TokenCertificateBinding ssl data not null (IF:1.1)"
  def x5t = exc?.identity?.attributes?.get("cnf")?.get("x5t#S256")?.asText()
  def sub = exc?.identity?.attributes?.get("sub")?.asText()
  def client_id = exc?.identity?.attributes?.get("client_id")?.asText()
    
    exc?.log.info x5t;
    exc?.log.info sub;
    exc?.log.info client_id;
    
  if (client_id != null && sub == null)
  {
      exc?.log.info "TokenCertificateBinding Client credentials flow detected"
      anything()
  } else {
      exc?.log.info "TokenCertificateBinding User flow detected, certificate expected to be bound to the user token"
    if (x5t != null)
    {
        exc?.log.info "TokenCertificateBinding x5t not null (IF:2)"
        x5tBytes = Base64.getUrlDecoder().decode(x5t)
        def certs = exc?.sslData.getClientCertificateChain()

        if (certs.isEmpty())
        {
        exc?.log.info "TokenCertificateBinding Mutual TLS sender constrained access token (x5t#S256=$x5t) presented on TLS connection with no MTLS client certificates"
        not(anything())
        }
        else
        {
        exc?.log.info "TokenCertificateBinding Certs not empty"
        def hasher = MessageDigest.getInstance("SHA-256")
        def clientCertHash = hasher.digest(certs.get(0).getEncoded())
        if (!Arrays.equals(x5tBytes, clientCertHash))
        {
            def certHash = Base64.getUrlEncoder().withoutPadding().encodeToString(clientCertHash)
            exc?.log.info "TokenCertificateBinding Mutual TLS Client Certificate (hash=$certHash) does not match the certificate to which the access token is bound (x5t#S256=$x5t)"
            not(anything())
        }
        else
        {
            exc?.log.info "TokenCertificateBinding Mutual TLS Client Certificate matches the certificate to which the access token is bound"
            anything()
        }
        }
    }	else {
        exc?.log.info "TokenCertificateBinding x5t null (IF-E:2)"
        not(anything())
        
    } 
  }
    } else {
    exc?.log.info "TokenCertificateBinding ssl data null (IF-E:1.1)"
  not(anything())
}
} else {
    exc?.log.info "TokenCertificateBinding request data null (IF-E:1)"
  not(anything())
}
