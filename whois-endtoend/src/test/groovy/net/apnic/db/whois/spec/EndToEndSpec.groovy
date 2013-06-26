package net.apnic.db.whois.spec

import net.ripe.db.whois.common.profiles.WhoisVariant

class EndToEndSpec extends net.ripe.db.whois.spec.EndToEndSpec {
    def setupSpec() {
        // Logging and profile setup is handled by base class
        // We only need to care about overriding the system properties
        WhoisVariant.setWhoIsVariant(WhoisVariant.Type.APNIC);
        System.setProperty("whois.maintainers.power", "APNIC-HM");
        System.setProperty("whois.maintainers.enduser", "");
        System.setProperty("whois.maintainers.alloc", "APNIC-HM");
        System.setProperty("whois.maintainers.enum", "");
        System.setProperty("whois.maintainers.dbm", "APNIC-HM");
    }

    // Override the basic fixtures for APNIC
    @Override
    Map<String, String> getBasicFixtures() {
        BasicFixtures.basicFixtures
    }
}
