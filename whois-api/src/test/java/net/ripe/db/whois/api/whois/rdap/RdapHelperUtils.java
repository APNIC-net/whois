package net.ripe.db.whois.api.whois.rdap;

import com.Ostermiller.util.LineEnds;
import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.io.xml.DomWriter;
import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.MultiThreadedHttpConnectionManager;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.io.IOUtils;
import org.apache.commons.io.output.ByteArrayOutputStream;
import org.codehaus.jackson.JsonFactory;
import org.codehaus.jackson.JsonGenerator;
import org.codehaus.jackson.JsonParser;
import org.codehaus.jackson.map.AnnotationIntrospector;
import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.map.SerializationConfig;
import org.codehaus.jackson.map.annotate.JsonSerialize;
import org.codehaus.jackson.map.introspect.JacksonAnnotationIntrospector;
import org.codehaus.jackson.xc.JaxbAnnotationIntrospector;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.ws.http.HTTPException;
import java.io.IOException;
import java.io.StringWriter;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.TimeZone;

public class RdapHelperUtils {
    private static final Logger LOGGER = LoggerFactory.getLogger(RdapHelperUtils.class);
    private static final XStream XSTREAM = new XStream();
    private static DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();

    protected static HttpClient httpClient = null;
    static {
        MultiThreadedHttpConnectionManager mgr = new MultiThreadedHttpConnectionManager();
        mgr.getParams().setDefaultMaxConnectionsPerHost(1000);
        mgr.getParams().setMaxTotalConnections(1000);
        httpClient = new HttpClient(mgr);
    }

    public static <T> T cloneObject(T src, Class dest) {
        String toXml = XSTREAM.toXML(src).replace(src.getClass().getName(), dest.getName());
        return (T) XSTREAM.fromXML(toXml);
    }

    public static String toXML(Object src) {
        return XSTREAM.toXML(src);
    }

    public static Object fromXML(String xstreamXml) {
        return XSTREAM.fromXML(xstreamXml);
    }

    public static Document toDOM(Object src) {
        Document doc = null;
        try {
            doc = docBuilderFactory.newDocumentBuilder().newDocument();
            XSTREAM.marshal(src, new DomWriter(doc));
        } catch (ParserConfigurationException pae) {
            LOGGER.error("toDOM failed", pae);
        }
        return doc;
    }

    public static String DOMToString(Document doc) {
        String ret = null;
        try {
            DOMSource domSource = new DOMSource(doc);
            StringWriter writer = new StringWriter();
            StreamResult result = new StreamResult(writer);
            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer transformer = tf.newTransformer();
            transformer.transform(domSource, result);
            ret = writer.toString();
        } catch (TransformerException ex) {
            LOGGER.error("DOMToString failed", ex);
        }
        return ret;
    }

    public static String convertEOLToUnix(String str) {
        ByteArrayOutputStream resultStream = new ByteArrayOutputStream();
        try {
            LineEnds.convert(IOUtils.toInputStream(str), resultStream, LineEnds.STYLE_UNIX);
        } catch (Exception ex) {
            LOGGER.error("convertEOLToUnix failed", ex);
        }
        return resultStream.toString();
    }

    public static byte[] getHttpContent(String url) {
        return getHttpHeaderAndContent(url).body;
    }

    public static HttpResponseElements getHttpContent(String url, boolean httpErrorsOk) {
        return getHttpHeaderAndContent(url, httpErrorsOk);
    }

    public static HttpResponseElements getHttpHeaderAndContent(String url) {
        return getHttpHeaderAndContent(url, false);
    }

    public static HttpResponseElements getHttpHeaderAndContent(String url, boolean httpErrorsOk, Header... headers) {
        // Create a method instance.
        GetMethod method = new GetMethod(url);
        for (Header header : headers) {
            method.setRequestHeader(header);
        }
        byte[] responseBody = new byte[0];
        int statusCode = -1;
        try {
            statusCode = httpClient.executeMethod(method);
            if (statusCode != HttpStatus.SC_OK && !httpErrorsOk) {
                throw new HttpException("Http error [" + statusCode + "][" + url + "]");
            }
            // Read the response body.
            responseBody = method.getResponseBody(1024 * 1024);
            method.getResponseHeaders("Content-Type");
        } catch (Exception ex) {
            LOGGER.error("Could not get url status=" + statusCode + ":" + url, ex);
            throw new HTTPException(statusCode);
        } finally {
            // Release the connection.
            method.releaseConnection();
        }
        return new HttpResponseElements( method.getResponseHeaders(), responseBody, statusCode);
    }

    public static String marshal(final Object o) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        final JsonFactory jsonFactory = createJsonFactory();
        final JsonGenerator generator = jsonFactory.createJsonGenerator(outputStream).useDefaultPrettyPrinter();
        generator.writeObject(o);
        generator.close();

        // So that the test can run on ALL platform (Curse you iScampi!!)
        return RdapHelperUtils.convertEOLToUnix(outputStream.toString());
    }

    public static <T> T unmarshal(final String content, Class<T> valueType) throws IOException {
        final JsonFactory jsonFactory = createJsonFactory();
        final JsonParser parser = jsonFactory.createJsonParser(content);
        return parser.readValueAs(valueType);
    }

    public static JsonFactory createJsonFactory() {
        final ObjectMapper objectMapper = new ObjectMapper();

        objectMapper.setAnnotationIntrospector(
                new AnnotationIntrospector.Pair(
                        new JacksonAnnotationIntrospector(),
                        new JaxbAnnotationIntrospector()));

        objectMapper.setSerializationInclusion(JsonSerialize.Inclusion.NON_NULL);
        objectMapper.configure(SerializationConfig.Feature.WRITE_EMPTY_JSON_ARRAYS, true);

        final DateFormat df = new SimpleDateFormat(RdapJsonProvider.RDAP_DATE_FORMAT);
        df.setTimeZone(TimeZone.getTimeZone("UTC"));
        objectMapper.setDateFormat(df);

        return objectMapper.getJsonFactory();
    }

    public static class HttpResponseElements {
        public Header[] headers;
        public byte[] body;
        public int statusCode;

        public HttpResponseElements(Header[] headers, byte[] body, int statusCode) {
            this.headers = headers;
            this.body = body;
            this.statusCode = statusCode;
        }

    }
}
