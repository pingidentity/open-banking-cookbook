# PingAccess Groovy Scripts

This contains the groovy scripts required to enforce MTLS between the TPP and the PingAccess on the ASPSP side

## Token Certificate Binding Rule.groovy

This rule validates that the signature of the MTLS client certificate that was used to swap an authorisation code for a token (representing a PSU after authentication and SCA) matches the signature of the MTLS client certificate that is presenting the same token (for example, to make an API request to complete a payment)

This script has been tested with the OAuth Groovy Script (for API resources) PingAccess rule

## Validate Certificate Chain Rule.groovy

This rule validates that a client certificate chain is presented to PingAccess for MTLS validation

This script has been tested with the OAuth Groovy Script (for API resources) and Groovy Script (for web resources) PingAccess rules

## Validate SNI Rule.groovy

This rule validates that a client certificate, that is presented to PingAccess for MTLS validation, contains SNI claims

This script has been tested with the OAuth Groovy Script (for API resources) and Groovy Script (for web resources) PingAccess rules