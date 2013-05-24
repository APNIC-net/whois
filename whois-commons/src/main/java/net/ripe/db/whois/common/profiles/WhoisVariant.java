package net.ripe.db.whois.common.profiles;

public class WhoisVariant {
    public static final String WHOIS_VARIANT = "whois.variant";
    public static final String WHOIS_VARIANT_VALUE = System.getProperty(WHOIS_VARIANT, "");
    public static final String WHOIS_VARIANT_APNIC = "apnic";

    public static boolean isAPNIC() {
        return System.getProperty(WHOIS_VARIANT, "").equals(WhoisValiantType.APNIC.getValue());
    }

    public enum WhoisValiantType {
        APNIC(WHOIS_VARIANT_APNIC);
        private final String value;

        WhoisValiantType(final String value) {
            this.value = value;
        }

        public String getValue() {
            return value;
        }
    }
}
