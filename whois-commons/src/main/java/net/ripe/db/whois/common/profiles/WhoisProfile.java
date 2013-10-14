package net.ripe.db.whois.common.profiles;

import org.springframework.core.env.AbstractEnvironment;

public class WhoisProfile {
    public static final String ENDTOEND = "ENDTOEND";
    public static final String TEST = "TEST";
    public static final String DEPLOYED = "DEPLOYED";
    private static boolean deployed, endtoend;

    public static boolean isDeployed() {
        return deployed;
    }

    public static void setDeployed() {
        WhoisProfile.deployed = true;
        WhoisProfile.endtoend = false;
        System.setProperty(AbstractEnvironment.ACTIVE_PROFILES_PROPERTY_NAME, DEPLOYED);
    }

    public static boolean isEndtoend() {
        return endtoend;
    }

    public static void setEndtoend() {
        WhoisProfile.deployed = false;
        WhoisProfile.endtoend = true;
        System.setProperty(AbstractEnvironment.ACTIVE_PROFILES_PROPERTY_NAME, ENDTOEND);
    }

    public static void reset() {
        WhoisProfile.deployed = false;
        WhoisProfile.endtoend = false;
        System.setProperty(AbstractEnvironment.ACTIVE_PROFILES_PROPERTY_NAME, "");
    }

}
