package net.ripe.db.whois.common.profiles;

public class WhoisVariant {
    public static final String WHOIS_VARIANT = "whois.variant";

    public static void setVariant(final String variant) {
        for (WhoisValiantType whoisConfigValue : WhoisValiantType.values()) {
            if (whoisConfigValue.getValue().equalsIgnoreCase(variant)) {
                System.setProperty(WHOIS_VARIANT, whoisConfigValue.getValue());
                break;
            }
        }
    }

    public static boolean isAPNIC() {
        return System.getProperty( WHOIS_VARIANT,"").equals(WhoisValiantType.APNIC.getValue());
    }

    public enum WhoisValiantType {
        APNIC("apnic");

        private final String value;
        WhoisValiantType(final String value) {
            this.value = value;
        }

        public String getValue() {
        return value;
        }
    }
}
