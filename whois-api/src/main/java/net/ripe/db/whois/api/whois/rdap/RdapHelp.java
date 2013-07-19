package net.ripe.db.whois.api.whois.rdap;

import com.google.common.collect.Lists;
import net.ripe.db.whois.api.whois.rdap.domain.Help;

import java.util.List;

public class RdapHelp {

    protected static final List<String> RDAP_CONFORMANCE_LEVEL = Lists.newArrayList("rdap_level_0");

    public static Object build (String selfUrl) {
        final Help help = new Help();

        help.getRdapConformance().addAll(RDAP_CONFORMANCE_LEVEL);
        help.getNotices().addAll(NoticeFactory.generateHelpNotices(selfUrl));

        return help;
    }
}
