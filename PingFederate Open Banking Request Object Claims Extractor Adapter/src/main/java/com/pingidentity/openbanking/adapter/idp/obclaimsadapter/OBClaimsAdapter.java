package com.pingidentity.openbanking.adapter.idp.obclaimsadapter;


import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.List;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.sourceid.saml20.adapter.AuthnAdapterException;
import org.sourceid.saml20.adapter.conf.Configuration;
import org.sourceid.saml20.adapter.gui.AdapterConfigurationGuiDescriptor;
import org.sourceid.saml20.adapter.idp.authn.AuthnPolicy;
import org.sourceid.saml20.adapter.idp.authn.IdpAuthenticationAdapter;
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

    private static final String ATTR_INTENT_ID = "openbanking_intent_id"; // the attribute name of the intent ID
    private static final String ATTR_ACR = "acr"; // the attribute name of the acr requested
    private static final String ACR_DEFAULT = "DEFAULT";
    
    private final IdpAuthnAdapterDescriptor descriptor;

    /**
     * Constructor for the Sample Subnet Adapter. Initializes the authentication adapter descriptor so PingFederate can
     * generate the proper configuration GUI
     */
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

    /**
     * The PingFederate server will invoke this method on your adapter implementation to discover metadata about the
     * implementation. This included the adapter's attribute contract and a description of what configuration fields to
     * render in the GUI. <br/>
     * <br/>
     * Your implementation of this method should return the same IdpAuthnAdapterDescriptor object from call to call -
     * behaviour of the system is undefined if this convention is not followed.
     * 
     * @return an IdpAuthnAdapterDescriptor object that describes this IdP adapter implementation.
     */
    public IdpAuthnAdapterDescriptor getAdapterDescriptor()
    {
        return descriptor;
    }

    /**
     * This is the method that the PingFederate server will invoke during processing of a single logout to terminate a
     * security context for a user at the external application or authentication provider service.
     * <p>
     * If your implementation of this method needs to operate asynchronously, it just needs to write to the
     * HttpServletResponse as appropriate and commit it. Right after invoking this method the PingFederate server checks
     * to see if the response has been committed. If the response has been committed, PingFederate saves the state it
     * needs and discontinues processing for the current transaction. Processing of the transaction is continued when
     * the user agent returns to the <code>resumePath</code> at the PingFederate server at which point the server
     * invokes this method again. This series of events will be repeated until this method returns without committing
     * the response. When that happens (which could be the first invocation) PingFederate will complete the protocol
     * transaction processing with the return result of this method.
     * </p>
     * <p>
     * Note that if the response is committed, then PingFederate ignores the return value. Only the return value of an
     * invocation that does not commit the response will be used. Accessing the HttpSession from the request is not
     * recommended and doing so is deprecated. Use {@link org.sourceid.saml20.adapter.state.SessionStateSupport} as an
     * alternative.
     * </p>
     * <p>
     * 
     * <b>Note on SOAP logout:</b> If this logout is being invoked as the result of a back channel protocol request, the
     * request, response and resumePath parameters will all be null as they have no meaning in such a context where the
     * user agent is inaccessible.
     * </p>
     * <p>
     * In this example, no extra action is needed to logout so simply return true.
     * </p>
     * 
     * @param authnIdentifiers
     *            the map of authentication identifiers originally returned to the PingFederate server by the
     *            {@link #lookupAuthN} method. This enables the adapter to associate a security context or session
     *            returned by lookupAuthN with the invocation of this logout method.
     * @param req
     *            the HttpServletRequest can be used to read cookies, parameters, headers, etc. It can also be used to
     *            find out more about the request like the full URL the request was made to.
     * @param resp
     *            the HttpServletResponse. The response can be used to facilitate an asynchronous interaction. Sending a
     *            client side redirect or writing (and flushing) custom content to the response are two ways that an
     *            invocation of this method allows for the adapter to take control of the user agent. Note that if
     *            control of the user agent is taken in this way, then the agent must eventually be returned to the
     *            <code>resumePath</code> endpoint at the PingFederate server to complete the protocol transaction.
     * @param resumePath
     *            the relative URL that the user agent needs to return to, if the implementation of this method
     *            invocation needs to operate asynchronously. If this method operates synchronously, this parameter can
     *            be ignored. The resumePath is the full path portion of the URL - everything after hostname and port.
     *            If the hostname, port, or protocol are needed, they can be derived using the HttpServletRequest.
     * @return a boolean indicating if the logout was successful.
     * @throws AuthnAdapterException
     *             for any unexpected runtime problem that the implementation cannot handle.
     * @throws IOException
     *             for any problem with I/O (typically any operation that writes to the HttpServletResponse will throw
     *             an IOException.
     * 
     * @see IdpAuthenticationAdapter#logoutAuthN(Map, HttpServletRequest, HttpServletResponse, String)
     */
    @SuppressWarnings("rawtypes")
    public boolean logoutAuthN(Map authnIdentifiers, HttpServletRequest req, HttpServletResponse resp, String resumePath)
            throws AuthnAdapterException, IOException
    {
        return true;
    }

    /**
     * This method is called by the PingFederate server to push configuration values entered by the administrator via
     * the dynamically rendered GUI configuration screen in the PingFederate administration console. Your implementation
     * should use the {@link Configuration} parameter to configure its own internal state as needed. The tables and
     * fields available in the Configuration object will correspond to the tables and fields defined on the
     * {@link org.sourceid.saml20.adapter.gui.AdapterConfigurationGuiDescriptor} on the AuthnAdapterDescriptor returned
     * by the {@link #getAdapterDescriptor()} method of this class. <br/>
     * <br/>
     * Each time the PingFederate server creates a new instance of your adapter implementation this method will be
     * invoked with the proper configuration. All concurrency issues are handled in the server so you don't need to
     * worry about them here. The server doesn't allow access to your adapter implementation instance until after
     * creation and configuration is completed.
     * 
     * @param configuration
     *            the Configuration object constructed from the values entered by the user via the GUI.
     */
    public void configure(Configuration configuration)
    {
 
    }

    /**
     * This method is used to retrieve information about the adapter (e.g. AuthnContext).
     * <p>
     * In this example the method not used, return null
     * </p>
     * 
     * @return a map
     */
    public Map<String, Object> getAdapterInfo()
    {
        return null;
    }

    /**
     * This is an extended method that the PingFederate server will invoke during processing of a single sign-on
     * transaction to lookup information about an authenticated security context or session for a user at the external
     * application or authentication provider service.
     * <p>
     * If your implementation of this method needs to operate asynchronously, it just needs to write to the
     * HttpServletResponse as appropriate and commit it. Right after invoking this method the PingFederate server checks
     * to see if the response has been committed. If the response has been committed, PingFederate saves the state it
     * needs and discontinues processing for the current transaction. Processing of the transaction is continued when
     * the user agent returns to the <code>resumePath</code> at the PingFederate server at which point the server
     * invokes this method again. This series of events will be repeated until this method returns without committing
     * the response. When that happens (which could be the first invocation) PingFederate will complete the protocol
     * transaction processing with the return result of this method.
     * </p>
     * <p>
     * Note that if the response is committed, then PingFederate ignores the return value. Only the return value of an
     * invocation that does not commit the response will be used.
     * </p>
     * <p>
     * If this adapter is implemented asynchronously, it's recommended that the user agent always returns to the <code>
     * resumePath</code> in order to be compatible with Composite Adapter's "Sufficent" adapter chaining policy. The
     * Composite Adapter allows an Administrator to "chain" a selection of available adapter instances for a connection.
     * At runtime, adapter chaining means that SSO requests are passed sequentially through each adapter instance
     * specified until one or more authentication results are found for the user. If the user agent does not return
     * control to PingFederate for failed authentication scenarios, then the authentication chain will break and should
     * not be used with Composite Adapter's "Sufficient" chaining policy.
     * </p>
     * <p>
     * In this example, we determine if the client (or the last proxy) is on the configured subnet. If the client has an
     * IPv6 address that's not ::1, fail immediately. If the user was previously authenticated by another adapter assign
     * it a corporate role, otherwise use the guest role.
     * </p>
     * 
     * @param req
     *            the HttpServletRequest can be used to read cookies, parameters, headers, etc. It can also be used to
     *            find out more about the request like the full URL the request was made to. Accessing the HttpSession
     *            from the request is not recommended and doing so is deprecated. Use
     *            {@link org.sourceid.saml20.adapter.state.SessionStateSupport} as an alternative.
     * @param resp
     *            the HttpServletResponse. The response can be used to facilitate an asynchronous interaction. Sending a
     *            client side redirect or writing (and flushing) custom content to the response are two ways that an
     *            invocation of this method allows for the adapter to take control of the user agent. Note that if
     *            control of the user agent is taken in this way, then the agent must eventually be returned to the
     *            <code>resumePath</code> endpoint at the PingFederate server to complete the protocol transaction.
     * @param inParameters
     *            A map that contains a set of input parameters. The input parameters provided are detailed in
     *            {@link IdpAuthenticationAdapterV2}, prefixed with <code>IN_PARAMETER_NAME_*</code> i.e.
     *            {@link IdpAuthenticationAdapterV2#IN_PARAMETER_NAME_RESUME_PATH}.
     * @return {@link AuthnAdapterResponse} The return value should not be null.
     * @throws AuthnAdapterException
     *             for any unexpected runtime problem that the implementation cannot handle.
     * @throws IOException
     *             for any problem with I/O (typically any operation that writes to the HttpServletResponse).
     */
    @SuppressWarnings("unchecked")
    public AuthnAdapterResponse lookupAuthN(HttpServletRequest req, HttpServletResponse resp,
            Map<String, Object> inParameters) throws AuthnAdapterException, IOException
    {

        String intent_id_extracted = null;
        String acr_extracted = null;

        String jwt = req.getParameter("request");

        System.out.println("JWT: " + jwt);

        // Build a JwtConsumer that doesn't check signatures or do any validation, as this will be done by PF anyway.
        JwtConsumer firstPassJwtConsumer = new JwtConsumerBuilder()
                .setSkipAllValidators()
                .setDisableRequireSignature()
                .setSkipSignatureVerification()
                .build();

        //The first JwtConsumer is basically just used to parse the JWT into a JwtContext object.
        JwtContext jwtContext;
		try {
            jwtContext = firstPassJwtConsumer.process(jwt);

            System.out.println("jwtContext: " + jwtContext.toString());
			
			Map<String, List<Object>> flattened = jwtContext.getJwtClaims().flattenClaims();
			
            intent_id_extracted = (String) flattened.get("claims.id_token.openbanking_intent_id.value").iterator().next();
            
            try {
            	acr_extracted = (String) flattened.get("claims.id_token.acr.value").iterator().next();
            } catch (NullPointerException e) {
            	//e.printStackTrace();
            	//This can reasonably be empty so don't re-throw
            	System.out.println("No acr value requested.  As it is optional, continue with no error");
            }
	        
        
		} catch (InvalidJwtException e) {
			// TODO Auto-generated catch block
            e.printStackTrace();
            throw new AuthnAdapterException(e.getLocalizedMessage());
        }
        
        /* END METHOD */

        AuthnAdapterResponse authnAdapterResponse = new AuthnAdapterResponse();

        authnAdapterResponse.setAuthnStatus(AUTHN_STATUS.FAILURE); // Set default
        
        if ((intent_id_extracted == null) || (intent_id_extracted.equals(""))) {
        	authnAdapterResponse.setAuthnStatus(AUTHN_STATUS.FAILURE); // Set failure if intent_id not present.  Not conformant to an OB flow.
        	
        } else {
        	HashMap<String, Object> attributes = new HashMap<String, Object>();

            attributes.put(ATTR_INTENT_ID, intent_id_extracted);
            
            if ((acr_extracted == null) || (acr_extracted.equals(""))) {
            	System.out.println("ACR not requested by TPP.  Setting default to let the policy tree config handle the rest");
            	acr_extracted = ACR_DEFAULT;
            	
            }
            	
            attributes.put(ATTR_ACR, acr_extracted);

            authnAdapterResponse.setAttributeMap(attributes);
            authnAdapterResponse.setAuthnStatus(AUTHN_STATUS.SUCCESS);
        	
        }

        return authnAdapterResponse;
    }

    /**
     * This method is deprecated. It is not called when IdpAuthenticationAdapterV2 is implemented. It is replaced by
     * {@link #lookupAuthN(HttpServletRequest, HttpServletResponse, Map)}
     * 
     * @deprecated
     */
    @SuppressWarnings(value = { "rawtypes" })
    public Map lookupAuthN(HttpServletRequest req, HttpServletResponse resp, String partnerSpEntityId,
            AuthnPolicy authnPolicy, String resumePath) throws AuthnAdapterException, IOException
    {
        throw new UnsupportedOperationException();
    }

}

