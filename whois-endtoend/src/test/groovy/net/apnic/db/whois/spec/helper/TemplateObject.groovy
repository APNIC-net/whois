package net.apnic.db.whois.spec.helper

import net.ripe.db.whois.common.support.DummyWhoisClient
import net.ripe.db.whois.query.QueryServer

class TemplateObject {
    private BufferedReader query;
    private String consumedQuery = null;

    private String objectType = "";
    private String objectDescription = "";
    private List<List<String>> basicTemplate = new ArrayList();
    private Map<String, String> attributeDescriptions = new HashMap<String,String>();

    public class TestTemplateParseException extends Exception {
        TestTemplateParseException(TemplateObject object, String message) {
            super(">>>>> Consumed Query:\n" + object.consumedQuery + "\n<<<<<\nError: " + message);
        }
    }

    private class TestTemplateParseEOQ extends Exception { }

    TemplateObject(String objectType) {
        this.objectType = objectType;
        parseTemplate();
    }

    public String getDescription() {
        return objectDescription;
    }

    public List<List<String>> getBasicTemplate() {
        return basicTemplate;
    }

    public String getAttributeDescription(String attribute) {
        return attributeDescriptions.containsKey(attribute) ? attributeDescriptions.get(attribute) : "";
    }

    private void getTemplate() {
        String whois = DummyWhoisClient.query(QueryServer.port, "-v " + objectType);
        this.query = new BufferedReader(new StringReader(whois));
    }

    private String readTemplateLine() {
        String line = query.readLine();
        if (line == null) throw new TestTemplateParseEOQ();
        if (consumedQuery == null) {
            consumedQuery = line;
        } else {
            consumedQuery += "\n";
            consumedQuery += line;
        }
        return line;
    }

    private void parseTemplate() {
        def tableRegexp = /^(.*?):\s+\[(.*?)\]\s+\[(.*?)\]\s+\[(.*?)\]/;
        def attrRegexp = /^[-a-z0-9]+$/;

        String line;

        // Get the object template
        getTemplate();

        // Skip the header(s)
        try {
            while (true) {
                line = readTemplateLine()
                if (line =~ /^The ${objectType} class:/) break;
            }
        } catch (TestTemplateParseEOQ e) {
            throw new TestTemplateParseException(this, "Unexpected end looking for template start");
        }

        // Parse object description
        try {
            readTemplateLine();
            while (true) {
                line = readTemplateLine();
                if (line =~ tableRegexp) break;
                objectDescription += line + "\n";
            }
        } catch (TestTemplateParseEOQ e) {
            throw new TestTemplateParseException(this, "Unexpected end processing object description");
        }
        objectDescription = objectDescription.stripIndent().trim();

        // Parse template table
        try {
            while (true) {
                def matcher = (line =~ tableRegexp);
                if (matcher.getCount() == 1) {
                    basicTemplate.add(matcher[0][1..4].collect { it.toString().trim() });
                } else if (matcher.getCount() > 1) {
                    throw new TestTemplateParseException(this, "Too many matches while processing template table");
                } else {
                    throw new TestTemplateParseException(this, "Unexpected end of template table");
                }
                line = readTemplateLine();
                if (line =~ /^$/) break;
            }
        } catch (TestTemplateParseEOQ e) {
            throw new TestTemplateParseException(this, "Unexpected end processing template table");
        }

        // Confirm table end
        try {
            if (! (readTemplateLine() =~ /^The content of the attributes of the ${objectType} class are defined below:/)) {
                throw new TestTemplateParseException(this, "Expecting start of attribute definitions");
            }
            readTemplateLine();
        } catch (TestTemplateParseEOQ e) {
            throw new TestTemplateParseException(this, "Unexpected end looking for attribute definitions");
        }

        // Process attribute definitions
        try {
            line = readTemplateLine();
            if (! (line =~ attrRegexp)) {
                throw new TestTemplateParseException(this, "Invalid start of attribute definitions");
            }
            while (true) {
                String currentAttribute = line;
                String attributeDescription = "";
                while (true) {
                    line = readTemplateLine();
                    if (line =~ attrRegexp) break;
                    if (line =~ /^%/) break;
                    attributeDescription += line + "\n";
                }
                attributeDescription = attributeDescription.stripIndent().trim();
                attributeDescriptions.put(currentAttribute, attributeDescription);
                if (line =~ /^%/) break;
            }
        } catch (TestTemplateParseEOQ e) {
            throw new TestTemplateParseException(this, "Unexpected end processing attribute definitions");
        }
    }

    @Override
    public String toString() {
        StringBuffer str = new StringBuffer();
        str.printf("Template for [%s]:\n", objectType);
        basicTemplate.each {
            str.printf("%-18s %-11s %-10s %s\n", it[0] + ":", "[" + it[1] + "]", "[" + it[2] + "]", "[" + it[3] + "]");
        }
        return str.toString();
    }

    public String toVerboseString() {
        StringBuffer str = new StringBuffer();
        str <<  ">>>>> " << objectType << " Template\n" << objectDescription << "\n-----\n";
        basicTemplate.each {
            str << it[0] << ": ";
            for (i in 1..3) {
                str << " [" << it[i] << "]";
            }
            str << "\n";
        }
        attributeDescriptions.each {
            str << "----- " << it.key << " description:\n" << it.value << "\n"
        }
        str << "<<<<<";
        return str.toString();
    }
}
