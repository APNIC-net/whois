package net.ripe.db.whois.api.whois.rdap;

import org.codehaus.jackson.jaxrs.JacksonJaxbJsonProvider;

import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.ext.Provider;

/**
 * Handles custom media type.
 * Could be a better way to inject other supported media types right into JacksonJaxbJsonProvider
 * but this works for now.
 */

@Provider
@Produces(RdapJsonProvider.CONTENT_TYPE_RDAP_JSON)
public class RdapJsonProvider extends JacksonJaxbJsonProvider {
    public static final String CONTENT_TYPE_RDAP_JSON = "application/rdap+json";
    public static final MediaType CONTENT_TYPE_RDAP_JSON_TYPE = new MediaType(CONTENT_TYPE_RDAP_JSON.split("/")[0], CONTENT_TYPE_RDAP_JSON.split("/")[1]);

    public RdapJsonProvider() {
        super();
    }
}
