package net.ripe.db.whois.common.profiles;

import net.ripe.db.whois.common.rpsl.*;

import java.util.Map;

public class WhoisVariantHelperFactory {

    public static Map<AttributeSyntax.AttributeSyntaxType, AttributeSyntax> getAttributeSyntaxMap() {
        Map<AttributeSyntax.AttributeSyntaxType, AttributeSyntax> ret = net.ripe.db.whois.common.rpsl.AttributeSyntaxImpl.getAttributeSyntaxMap();
        if (WhoisVariant.isAPNIC()) {
            return net.apnic.db.whois.common.rpsl.AttributeSyntaxImpl.getAttributeSyntaxMap();
        }
        return ret;
    }

    public static Map<AttributeTypeBuilder.Enum, AttributeTypeBuilder> getAttributeTypeBuilderMap() {
        Map<AttributeTypeBuilder.Enum, AttributeTypeBuilder> ret = new AttributeTypeBuilderImpl(null, null, null).getAttributeTypeBuilderMap();
        if (WhoisVariant.isAPNIC()) {
            return new net.apnic.db.whois.common.rpsl.AttributeTypeBuilderImpl(null, null, null).getAttributeTypeBuilderMap();
        }
        return ret;
    }

    public static Map<ObjectType, String> getObjectDocumentationMap() {
        Map<ObjectType, String> ret = net.ripe.db.whois.common.rpsl.ObjectDocumentationConfig.getDocumentationImpl();
        if (WhoisVariant.isAPNIC()) {
            return net.apnic.db.whois.common.rpsl.ObjectDocumentationConfig.getDocumentationImpl();
        }
        return ret;
    }

    public static Map<ObjectType, ObjectTemplate> getObjectTemplateMap() {
        Map<ObjectType, ObjectTemplate> ret = ObjectTemplateMapConfig.getTemplateMap();

        if (WhoisVariant.isAPNIC()) {
            return net.apnic.db.whois.common.rpsl.ObjectTemplateMapConfig.getTemplateMap();
        }
        return ret;
    }

    public static String getDbmEmailPostfixRegex() {
        String ret = "\\-dbm@ripe\\.net";

        if (WhoisVariant.isAPNIC()) {
            ret = "\\-dbm@apnic\\.net";
        }
        return ret;
    }
}
