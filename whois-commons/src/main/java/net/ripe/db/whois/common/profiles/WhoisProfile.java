package net.ripe.db.whois.common.profiles;

import org.apache.commons.lang.StringUtils;

public class WhoisProfile {
    public static final String ENDTOEND = "ENDTOEND";
    public static final String TEST = "TEST";
    public static final String DEPLOYED = "DEPLOYED";

    public static void setActive(final String... profiles) {
        StringBuilder result = new StringBuilder();
        for (String profile : profiles) {
            if (StringUtils.isNotEmpty(profile)) {
                result.append(",").append(profile);
            }
        }
        if (result.length() > 0) {
            System.setProperty("spring.profiles.active", result.toString().substring(1));
        }
    }
}
