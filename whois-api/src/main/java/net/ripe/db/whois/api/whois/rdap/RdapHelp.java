package net.ripe.db.whois.api.whois.rdap;

import net.ripe.db.whois.api.whois.rdap.domain.Help;
import net.ripe.db.whois.api.whois.rdap.NoticeFactory;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;

public class RdapHelp {

    @Autowired
    private static NoticeFactory noticeFactory;

    public static Object build (String selfUrl) {
        final Help help = new Help();

        help.getRdapConformance().addAll(RdapObjectMapper.RDAP_CONFORMANCE_LEVEL);
        help.getNotices().addAll(noticeFactory.generateHelpNotices(selfUrl));

        return help;
    }
}
