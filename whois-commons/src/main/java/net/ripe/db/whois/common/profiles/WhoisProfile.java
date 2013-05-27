package net.ripe.db.whois.common.profiles;

import org.apache.commons.lang.StringUtils;

public class WhoisProfile {
    public static final String ENDTOEND = "ENDTOEND";
    public static final String TEST = "TEST";
    public static final String DEPLOYED = "DEPLOYED";
    public static String variant;
    private static boolean deployed, endtoend;

    static void setActive() {
        StringBuilder result = new StringBuilder();

        if (deployed) {
            result.append(DEPLOYED);
        }
        else {
            result.append(ENDTOEND);
        }

        if (StringUtils.isNotEmpty(variant)) {
            result.append(",").append(variant);
        }

        System.setProperty("spring.profiles.active", result.toString());
    }

    public static boolean isDeployed() {
        return deployed;
    }

    public static void setDeployed() {
        WhoisProfile.deployed = true;
        WhoisProfile.endtoend = false;
        setActive();
    }

    public static boolean isEndtoend() {
        return endtoend;
    }

    public static void setEndtoend() {
        WhoisProfile.deployed = false;
        WhoisProfile.endtoend = true;
        setActive();
    }

    public static final String getWhoisVariant() {
        return variant;
    }

    public static void setWhoisVariant(final String whoisVariant) {
        variant = whoisVariant;
        setActive();
    }
}
