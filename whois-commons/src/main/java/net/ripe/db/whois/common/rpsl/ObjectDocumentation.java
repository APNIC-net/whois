package net.ripe.db.whois.common.rpsl;

import net.ripe.db.whois.common.profiles.WhoisVariantHelperFactory;

import java.util.Map;

class ObjectDocumentation {
    private static final Map<ObjectType, String> DOCUMENTATION = WhoisVariantHelperFactory.getObjectDocumentationMap();

    public static String getDocumentation(final ObjectType objectType) {
        final String s = DOCUMENTATION.get(objectType);
        if (s == null) {
            return "";
        }

        return s;
    }
}
