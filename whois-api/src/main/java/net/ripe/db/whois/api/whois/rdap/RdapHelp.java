package net.ripe.db.whois.api.whois.rdap;

import net.ripe.db.whois.api.whois.rdap.domain.Help;

public class RdapHelp {

    public static Object build (String selfUrl) {
        final Help help = new Help();

        help.getRdapConformance().addAll(RdapObjectMapper.RDAP_CONFORMANCE_LEVEL);
        help.getNotices().addAll(NoticeFactory.generateHelpNotices(selfUrl));

        return help;
    }
}
