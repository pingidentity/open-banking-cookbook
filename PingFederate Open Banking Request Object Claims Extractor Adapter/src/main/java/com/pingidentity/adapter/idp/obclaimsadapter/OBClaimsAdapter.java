package com.pingidentity.adapter.idp.obclaimsadapter;


import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.List;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.sourceid.saml20.adapter.AuthnAdapterException;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.gui.AdapterConfigurationGuiDescriptor;
import org.sourceid.saml20.adapter.idp.authn.AuthnPolicy;
import org.sourceid.saml20.adapter.idp.authn.IdpAuthnAdapterDescriptor;

import com.pingidentity.sdk.AuthnAdapterResponse;
import com.pingidentity.sdk.AuthnAdapterResponse.AUTHN_STATUS;
import com.pingidentity.sdk.IdpAuthenticationAdapterV2;

import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.jwt.consumer.JwtContext;


public class OBClaimsAdapter implements IdpAuthenticationAdapterV2
{

	private static final Log LOG = LogFactory.getLog(OBClaimsAdapter.class);
    private static final String ATTR_INTENT_ID = "openbanking_intent_id"; // the attribute name of the intent ID
    private static final String ATTR_ACR = "acr"; // the attribute name of the acr requested
    private static final String ACR_DEFAULT = "DEFAULT";
    
    private final IdpAuthnAdapterDescriptor descriptor;

    public OBClaimsAdapter()
    {
        
        // Create a GUI descriptor
        AdapterConfigurationGuiDescriptor guiDescriptor = new AdapterConfigurationGuiDescriptor(
                "Open Banking Request Object Claims Extraction Adapter");

        // Create the Idp authentication adapter descriptor
        Set<String> contract = new HashSet<String>();
        contract.add(ATTR_INTENT_ID);
        contract.add(ATTR_ACR);
        descriptor = new IdpAuthnAdapterDescriptor(this, "Open Banking Request Object Claims Extraction Adapter", contract, false, guiDescriptor, false);
    }

    
    public IdpAuthnAdapterDescriptor getAdapterDescriptor()
    {
        return descriptor;
    }


    @SuppressWarnings("rawtypes")
    public boolean logoutAuthN(Map authnIdentifiers, HttpServletRequest req, HttpServletResponse resp, String resumePath)
            throws AuthnAdapterException, IOException
    {
        return true;
    }


    public void configure(Configuration configuration)
    {
 
    }


    public Map<String, Object> getAdapterInfo()
    {
        return null;
    }


    @SuppressWarnings("unchecked")
    public AuthnAdapterResponse lookupAuthN(HttpServletRequest req, HttpServletResponse resp,
            Map<String, Object> inParameters) throws AuthnAdapterException, IOException
    {

        String intent_id_extracted = null;
        String acr_extracted = null;

        String jwt = req.getParameter("request");
        
        AuthnAdapterResponse authnAdapterResponse = new AuthnAdapterResponse();
        authnAdapterResponse.setAuthnStatus(AUTHN_STATUS.FAILURE); // Set default

        if (jwt != null) {
        	LOG.debug("Retrieved Request Object JWT: " + jwt);
	
	        // Build a JwtConsumer that doesn't check signatures or do any validation, as this will have been done by PF anyway.  For production code this can be enhanced
	        JwtConsumer firstPassJwtConsumer = new JwtConsumerBuilder()
	                .setSkipAllValidators()
	                .setDisableRequireSignature()
	                .setSkipSignatureVerification()
	                .build();
	
	        //The first JwtConsumer is basically just used to parse the JWT into a JwtContext object.
	        JwtContext jwtContext;
			try {
	            jwtContext = firstPassJwtConsumer.process(jwt);
	
	            LOG.debug("JWT Context processing result: " + jwtContext.toString());
				
				Map<String, List<Object>> flattened = jwtContext.getJwtClaims().flattenClaims();
				
				try {
		            intent_id_extracted = (String) flattened.get("claims.id_token.openbanking_intent_id.value").iterator().next();
				} catch (NullPointerException e) {
	            	
					LOG.error("No openbanking_intent_id value requested in the request object.  This is required");
	            	throw new AuthnAdapterException("openbanking_intent_id not present in the request object");
	            }
				
	            try {
	            	acr_extracted = (String) flattened.get("claims.id_token.acr.value").iterator().next();
	            } catch (NullPointerException e) {
	            	
	            	//This can reasonably be empty as acr is optional so don't re-throw
	            	LOG.debug("No acr value requested in the Request Object.  As it is optional, continue with no error");
	            }
		        
	        
			} catch (InvalidJwtException e) {
				
	            LOG.error(e.getLocalizedMessage());
	            throw new AuthnAdapterException(e.getLocalizedMessage());
	        }
	        
	        
	        if ((intent_id_extracted == null) || (intent_id_extracted.equals(""))) {
	        	LOG.error("No openbanking_intent_id value requested in the request object.  This is required");
            	throw new AuthnAdapterException("openbanking_intent_id not present in the request object");
	        	
	        } else {
	        	HashMap<String, Object> attributes = new HashMap<String, Object>();
	
	            attributes.put(ATTR_INTENT_ID, intent_id_extracted);
	            
	            if ((acr_extracted == null) || (acr_extracted.equals(""))) {
	            	LOG.debug("ACR not requested by TPP.  Setting default to let the policy tree config handle the rest");
	            	acr_extracted = ACR_DEFAULT;
	            	
	            }
	            	
	            attributes.put(ATTR_ACR, acr_extracted);
	
	            authnAdapterResponse.setAttributeMap(attributes);
	            authnAdapterResponse.setAuthnStatus(AUTHN_STATUS.SUCCESS);
	        	
	        }
        } else {
        	LOG.error("Request Object cannot be found.  This is required");
        	throw new AuthnAdapterException("Request Object not present in the request");
        }

        return authnAdapterResponse;
    }


    @SuppressWarnings(value = { "rawtypes" })
    public Map lookupAuthN(HttpServletRequest req, HttpServletResponse resp, String partnerSpEntityId,
            AuthnPolicy authnPolicy, String resumePath) throws AuthnAdapterException, IOException
    {
        throw new UnsupportedOperationException();
    }

}

