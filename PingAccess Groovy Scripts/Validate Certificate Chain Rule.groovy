exc?.log.warn "*** ValidateClientCertificateChain start"
if(exc?.getSslData()?.getClientCertificateChain()?.isEmpty())
{
  exc?.log.warn "*** ValidateClientCertificateChain fail"
  fail();
}
else
{
  exc?.log.warn "*** ValidateClientCertificateChain pass"
  pass();
}