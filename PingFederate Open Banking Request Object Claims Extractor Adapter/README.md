# PingFederate Open Banking Request Object Claims Extractor Adapter

## Overview

This is an example PingFederate custom adapter required to support extraction of the openbanking_intent_id from OIDC/OAuth request objects, created by TPPs, for use in the policy tree

Specifically it will extract the values of the following claims from the "claims" parameter of the request object:
* openbanking_intent_id
* acr

The openbanking_intent_id value is used by PingFederate (in policy tree configuration) to link the account or payment request intent throughout each stage of the authentication process

The acr value is expected to be used by PingFederate (in policy tree configuration) to determine whether the PSU should follow CA (Customer Authentication) or SCA (Secure Customer Authentication), as requested by the TPP

## System Requirements and Dependencies

* PingFederate 9.1 or higher


## Installation

* Copy the source from `src/main/java` to the PingFederate server's SDK examples folder: `<PF_INSTALL>/pingfederate/sdk/plugin-src/open-banking-claims-plugin/java`
* Follow the build instructions in the [PingFederate SDK Developer's Guide](https://documentation.pingidentity.com/pingfederate/pf91/index.shtml#sdkDevelopersGuide/concept/buildingAndDeployingYourProject.html) to compile and deploy the plug-in.
* Restart PingFederate.
* When running in a clustered environment, ensure that the resulting plug-in .jar file is copied into every node under: `<PF_INSTALL>/pingfederate/server/default/deploy`. Restart each PingFederate node to ensure the plug-in is loaded.


## Configuration

* In the PingFederate administrative console, navigate to: Identity Provider > Adapters
* Create a new adapter instance of type Open Banking Request Object Claims Extraction Adapter
* Add additional contract attributes if required
* Use openbanking_intent_id as the Pseudonym
* Map the acr and the openbanking_intent_id contract attributes to the adapter
* Ensure the adapter is saved
* When running in a clustered environment, be sure to replicate the configuration updates to other nodes.

## Support

Please report issues using the project's [issue tracker](https://github.com/pingidentity/open-banking-cookbook/issues).