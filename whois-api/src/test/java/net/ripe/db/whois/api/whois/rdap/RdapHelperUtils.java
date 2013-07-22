package net.ripe.db.whois.api.whois.rdap;

import com.Ostermiller.util.LineEnds;
import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.io.xml.DomWriter;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.methods.GetMethod;
import org.codehaus.jackson.JsonFactory;
import org.codehaus.jackson.JsonGenerator;
import org.codehaus.jackson.JsonParser;
import org.codehaus.jackson.map.AnnotationIntrospector;
import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jackson.map.SerializationConfig;
import org.codehaus.jackson.map.annotate.JsonSerialize;
import org.codehaus.jackson.map.introspect.JacksonAnnotationIntrospector;
import org.codehaus.jackson.xc.JaxbAnnotationIntrospector;
import org.codehaus.plexus.util.StringInputStream;
import org.codehaus.plexus.util.StringOutputStream;
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
import java.io.IOException;
import java.io.StringWriter;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.TimeZone;

public class RdapHelperUtils {
    private static final Logger LOGGER = LoggerFactory.getLogger(RdapHelperUtils.class);
    private static final XStream XSTREAM = new XStream();
    private static DocumentBuilderFactory docBuilderFactory = DocumentBuilderFactory.newInstance();

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

    public static String convertEOLToUnix(StringOutputStream serializer) {
        StringOutputStream resultStream = new StringOutputStream();
        try {
            LineEnds.convert(new StringInputStream(serializer.toString()), resultStream, LineEnds.STYLE_UNIX);
        } catch (Exception ex) {
            LOGGER.error("convertEOLToUnix failed", ex);
        }
        return resultStream.toString();
    }

    public static String convertEOLToUnix(String str) {
        StringOutputStream resultStream = new StringOutputStream();
        try {
            LineEnds.convert(new StringInputStream(str), resultStream, LineEnds.STYLE_UNIX);
        } catch (Exception ex) {
            LOGGER.error("convertEOLToUnix failed", ex);
        }
        return resultStream.toString();
    }

    public static byte[] getHttpContent(String url) {
        // Create a method instance.
        final HttpClient httpClient = new HttpClient();
        GetMethod method = new GetMethod(url);
        byte[] responseBody = new byte[0];
        int statusCode = -1;
        try {
            statusCode = httpClient.executeMethod(method);
            if (statusCode != HttpStatus.SC_OK) {
                throw new HttpException("Http error [" + statusCode + "][" + url + "]");
            }
            // Read the response body.
            responseBody = method.getResponseBody();
        } catch (Exception ex) {
            LOGGER.error("Could not get url status=" + statusCode + ":" + url, ex);
        } finally {
            // Release the connection.
            method.releaseConnection();
        }
        return responseBody;
    }

    public static String marshal(final Object o) throws IOException {
        final StringOutputStream outputStream = new StringOutputStream();

        final JsonFactory jsonFactory = createJsonFactory();
        final JsonGenerator generator = jsonFactory.createJsonGenerator(outputStream).useDefaultPrettyPrinter();
        generator.writeObject(o);
        generator.close();

        // So that the test can run on ALL platform (Curse you iScampi!!)
        return RdapHelperUtils.convertEOLToUnix(outputStream);
    }

    public static <T> T unmarshal(final String content,Class<T> valueType) throws IOException {
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

}
