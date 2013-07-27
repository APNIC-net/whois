package net.ripe.db.whois.api.whois.rdap;

import com.google.common.collect.Lists;
import net.ripe.db.whois.api.whois.rdap.domain.Notice;
import net.ripe.db.whois.common.rpsl.AttributeType;
import net.ripe.db.whois.common.rpsl.RpslObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.core.io.Resource;

import java.io.IOException;
import java.util.List;
import java.util.Properties;

public class NoticeFactory {
    private static final Logger LOGGER = LoggerFactory.getLogger(NoticeFactory.class);

    private static String tncTitle;
    private static String tncDescription;
    private static String tncLinkRel;
    private static String tncLinkHref;
    private static String tncLinkType;
    private static String filterIsFiltered;
    private static String filterDescription;
    private static String filterTitle;
    private static String sourceDescription;
    private static String sourceTitle;
    private static String helpTitle;
    private static String helpDescription;
    private static String helpLinkRel;
    private static String helpLinkHref;
    private static String helpLinkType;

    static {
        try {

            Properties properties = new Properties();
            ApplicationContext appContext = new ClassPathXmlApplicationContext();
            Resource resource = appContext.getResource(WhoisRdapService.RDAP_PROPERTIES);
            properties.load(resource.getInputStream());

            tncTitle = propertyCheck(properties,"rdap.tnc.title");
            tncDescription = propertyCheck(properties,"rdap.tnc.description");
            tncLinkRel = propertyCheck(properties,"rdap.tnc.linkrel");
            tncLinkHref = propertyCheck(properties,"rdap.tnc.linkhref");
            tncLinkType = propertyCheck(properties,"rdap.tnc.linktype");
            filterIsFiltered = propertyCheck(properties,"rdap.filter.isfiltered");
            filterDescription = propertyCheck(properties,"rdap.filter.description");
            filterTitle = propertyCheck(properties,"rdap.filter.title");
            sourceDescription = propertyCheck(properties,"rdap.source.description");
            sourceTitle = propertyCheck(properties,"rdap.source.title");
            helpTitle = propertyCheck(properties,"rdap.help.title");
            helpDescription = propertyCheck(properties,"rdap.help.description");
            helpLinkRel = propertyCheck(properties,"rdap.help.link.rel");
            helpLinkHref = propertyCheck(properties,"rdap.help.link.href");
            helpLinkType = propertyCheck(properties,"rdap.help.link.type");
        } catch (IOException ioex) {
            String error = String.format("Failed to load properties file [%s]", WhoisRdapService.RDAP_PROPERTIES);
            LOGGER.error(error);
            throw new ExceptionInInitializerError(error);
        }
    }

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
            String error = String.format("Missing property [%s] from [%s]", key, WhoisRdapService.RDAP_PROPERTIES);
            LOGGER.error(error);
            throw new ExceptionInInitializerError(error);
        }
        return value;
    }
}
