package net.ripe.db.whois.api.whois.rdap;

import com.google.common.collect.Lists;
import net.ripe.db.whois.api.whois.rdap.domain.Notice;
import net.ripe.db.whois.common.rpsl.AttributeType;
import net.ripe.db.whois.common.rpsl.RpslObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Properties;

@Component
public class NoticeFactory {
    private static final Logger LOGGER = LoggerFactory.getLogger(NoticeFactory.class);

    private static final String tncTitle  = propertyCheck(WhoisRdapService.getProperties(),"rdap.tnc.title");
    private static String tncDescription = propertyCheck(WhoisRdapService.getProperties(),"rdap.tnc.description");
    private static String tncLinkRel = propertyCheck(WhoisRdapService.getProperties(),"rdap.tnc.linkrel");
    private static String tncLinkHref = propertyCheck(WhoisRdapService.getProperties(),"rdap.tnc.linkhref");
    private static String tncLinkType = propertyCheck(WhoisRdapService.getProperties(),"rdap.tnc.linktype");
    private static String filterIsFiltered = propertyCheck(WhoisRdapService.getProperties(),"rdap.filter.isfiltered");
    private static String filterDescription = propertyCheck(WhoisRdapService.getProperties(),"rdap.filter.description");
    private static String filterTitle = propertyCheck(WhoisRdapService.getProperties(),"rdap.filter.title");
    private static String sourceDescription = propertyCheck(WhoisRdapService.getProperties(),"rdap.source.description");
    private static String sourceTitle = propertyCheck(WhoisRdapService.getProperties(),"rdap.source.title");
    private static String helpTitle = propertyCheck(WhoisRdapService.getProperties(),"rdap.help.title");
    private static String helpDescription = propertyCheck(WhoisRdapService.getProperties(),"rdap.help.description");
    private static String helpLinkRel = propertyCheck(WhoisRdapService.getProperties(),"rdap.help.link.rel");
    private static String helpLinkHref = propertyCheck(WhoisRdapService.getProperties(),"rdap.help.link.href");
    private static String helpLinkType = propertyCheck(WhoisRdapService.getProperties(),"rdap.help.link.type");

    private NoticeFactory() {
    }

    public static List<Notice> generateNotices(String selfLink) {
        List<Notice> notices = Lists.newArrayList();
        Notice tnc = new Notice();
        tnc.setTitle(tncTitle);
        tnc.getDescription().add(tncDescription);
        tnc.getLinks().add(RdapObjectMapper.createLink(tncLinkRel, selfLink, tncLinkHref, tncLinkType));
        notices.add(tnc);

        if (Boolean.parseBoolean(filterIsFiltered)) {
            Notice filtered = new Notice();
            filtered.setTitle(filterTitle);
            filtered.getDescription().add(filterDescription);
            notices.add(filtered);
        }
        return notices;
    }

    public static List<Notice> generateObjectNotices(RpslObject rpslObject, String selfLink) {
        List<Notice> notices = generateNotices(selfLink);
        Notice source = new Notice();
        source.setTitle(sourceTitle);
        source.getDescription().add(sourceDescription);
        source.getDescription().add(rpslObject.getValueForAttribute(AttributeType.SOURCE).toString());
        notices.add(source);
        return notices;
    }

    public static List<Notice> generateHelpNotices(String selfUrl) {
        List<Notice> notices = Lists.newArrayList();
        Notice authNotice = new Notice();
        authNotice.setTitle(helpTitle);
        authNotice.getDescription().add(helpDescription);
        authNotice.getLinks().add(RdapObjectMapper.createLink(helpLinkRel, selfUrl, helpLinkHref, helpLinkType));
        notices.add(authNotice);
        return notices;
    }

    private static String propertyCheck(Properties properties, String key) {
        String value = properties.getProperty(key);
        if (value == null) {
            String error = String.format("Missing property [%s] from [%s]", key, WhoisRdapService.rdapPropertiesPath);
            LOGGER.error(error);
            throw new ExceptionInInitializerError(error);
        }
        return value;
    }
}
