package net.ripe.db.whois.common.rpsl;

import net.ripe.db.whois.common.profiles.WhoisConfig;

import java.util.Map;

class ObjectDocumentation {
    private static final Map<ObjectType, String> DOCUMENTATION = WhoisConfig.isAPNIC() ?
                    net.apnic.db.whois.common.rpsl.ObjectDocumentationConfig.getDocumentationImpl() :
                    ObjectDocumentationConfig.getDocumentationImpl();

    public static String getDocumentation(final ObjectType objectType) {
        final String s = DOCUMENTATION.get(objectType);
        if (s == null) {
            return "";
        }

        return s;
    }
}
