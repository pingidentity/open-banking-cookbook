exc?.log.warn "*** ValidateSNI start"
if(exc?.getSslData()?.getSniServerNames()?.isEmpty())
{
  exc?.log.warn "*** ValidateSNI fail"
  fail();
}
else
{
  exc?.log.warn "*** ValidateSNI pass"
  pass();
}