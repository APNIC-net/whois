package net.ripe.db.whois.api.whois.rdap;

import org.codehaus.jackson.jaxrs.JacksonJaxbJsonProvider;

import javax.ws.rs.Consumes;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.ext.Provider;

/**
 * Handles rdap+json media type.
 */

@Provider
@Consumes({ RdapJsonProvider.CONTENT_TYPE_RDAP_JSON, MediaType.APPLICATION_JSON})
@Produces({ RdapJsonProvider.CONTENT_TYPE_RDAP_JSON, MediaType.APPLICATION_JSON})
public class RdapJsonProvider extends JacksonJaxbJsonProvider {
    public static final String CONTENT_TYPE_RDAP_JSON = "application/rdap+json";
    public static final MediaType CONTENT_TYPE_RDAP_JSON_TYPE = new MediaType(CONTENT_TYPE_RDAP_JSON.split("/")[0], CONTENT_TYPE_RDAP_JSON.split("/")[1]);

}
