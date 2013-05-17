package net.ripe.db.whois.common.profiles;

public class WhoisConfig {
    public static final String WHOIS_CONFIG = "whois.config";

    public static void setConfig(final String config) {
        for (WhoisConfigParam whoisConfigValue : WhoisConfigParam.values()) {
            if (whoisConfigValue.getValue().equalsIgnoreCase(config)) {
                System.setProperty(WHOIS_CONFIG, whoisConfigValue.getValue());
                break;
            }
        }
    }

    public static boolean isAPNIC() {
        return System.getProperty( WHOIS_CONFIG,"").equals(WhoisConfig.WhoisConfigParam.APNIC.getValue());
    }

    public enum WhoisConfigParam {
        APNIC("apnic");

        private final String value;
        WhoisConfigParam(final String value) {
            this.value = value;
        }

        public String getValue() {
        return value;
        }
    }
}
