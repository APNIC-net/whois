package net.ripe.db.whois.api.whois.rdap;

import com.thoughtworks.xstream.XStream;
import com.thoughtworks.xstream.io.xml.DomWriter;
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
import java.io.StringWriter;

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


}
