package net.ripe.db.whois.api.whois.rdap;

import org.codehaus.jackson.jaxrs.JacksonJaxbJsonProvider;
import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.map.SerializationConfig;

import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.ext.Provider;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.TimeZone;

/**
 * Handles rdap+json media type. Also allows requests via browsers.
 */

@Provider
@Produces({ RdapJsonProvider.CONTENT_TYPE_RDAP_JSON, MediaType.APPLICATION_JSON, MediaType.TEXT_PLAIN})
public class RdapJsonProvider extends JacksonJaxbJsonProvider {
    public static final String CONTENT_TYPE_RDAP_JSON = "application/rdap+json";
    public static final MediaType CONTENT_TYPE_RDAP_JSON_TYPE = new MediaType(CONTENT_TYPE_RDAP_JSON.split("/")[0], CONTENT_TYPE_RDAP_JSON.split("/")[1]);

    public static final String RDAP_DATE_FORMAT = "yyyy-MM-dd'T'HH:mm:ssXXX";

    public RdapJsonProvider() {
        configure(SerializationConfig.Feature.INDENT_OUTPUT, true);
        // TODO find a non-deprecated one of these
        configure(SerializationConfig.Feature.WRITE_NULL_PROPERTIES,false);
        configure(SerializationConfig.Feature.WRITE_DATES_AS_TIMESTAMPS, false);
        ObjectMapper mapper = locateMapper(null, null);
        DateFormat df = new SimpleDateFormat(RDAP_DATE_FORMAT);
        df.setTimeZone(TimeZone.getTimeZone("UTC"));
        mapper.setDateFormat(df);
    }

    /**
     * Allow browser interaction with text/plain.
     */
    protected boolean isJsonType(MediaType mediaType)
    {
        boolean ret;
        if (mediaType != null && mediaType.toString().equals(MediaType.TEXT_PLAIN)) {
            ret = true;
        } else {
            ret = super.isJsonType(mediaType);
        }
        return ret;
    }
}
