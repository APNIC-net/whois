package net.ripe.db.whois.api.whois.rdap;

import com.google.common.collect.Lists;
import net.ripe.db.whois.api.whois.rdap.domain.Notice;
import net.ripe.db.whois.common.rpsl.AttributeType;
import net.ripe.db.whois.common.rpsl.RpslObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;

import java.util.List;
import java.util.Properties;

@Component
public class NoticeFactory {

    private final String tncTitle;
    private final String tncDescription;
    private final String tncLinkRel;
    private final String tncLinkHref;
    private final String tncLinkType;
    private final String filterIsFiltered;
    private final String filterDescription;
    private final String filterTitle;
    private final String sourceDescription;
    private final String sourceTitle;
    private final String helpTitle;
    private final String helpDescription;
    private final String helpLinkRel;
    private final String helpLinkHref;
    private final String helpLinkType;

    @Autowired
    public NoticeFactory(@Value("${rdap.tnc.title:}") final String tncTitle,
                         @Value("${rdap.tnc.description:}") final String tncDescription,
                         @Value("${rdap.tnc.linkrel:}") final String tncLinkrel,
                         @Value("${rdap.tnc.linkhref:}") final String linkHref,
                         @Value("${rdap.tnc.linktype:}") final String linkType,
                         @Value("${rdap.filter.isfiltered:}") final String filtered,
                         @Value("${rdap.filter.description:}") final String filterDescription,
                         @Value("${rdap.filter.title:}") final String filterTitle,
                         @Value("${rdap.source.description:}") final String sourceDescription,
                         @Value("${rdap.source.title:}") final String sourceTitle,
                         @Value("${rdap.help.title:}") final String helpTitle,
                         @Value("${rdap.help.description:}") final String helpDescription,
                         @Value("${rdap.help.link.rel:}") final String helpLinkRel,
                         @Value("${rdap.help.link.href:}") final String helpLinkHref,
                         @Value("${rdap.help.link.type:}") final String helpLinkType) {
        this.tncTitle = tncTitle;
        this.tncDescription = tncDescription;
        this.tncLinkRel = tncLinkrel;
        this.tncLinkHref = linkHref;
        this.tncLinkType = linkType;
        this.filterIsFiltered = filtered;
        this.filterDescription = filterDescription;
        this.filterTitle = filterTitle;
        this.sourceDescription = sourceDescription;
        this.sourceTitle = sourceTitle;
        this.helpTitle = helpTitle;
        this.helpDescription = helpDescription;
        this.helpLinkRel = helpLinkRel;
        this.helpLinkHref = helpLinkHref;
        this.helpLinkType = helpLinkType;
    }

    public List<Notice> generateResponseNotices(String selfLink) {
        List<Notice> notices = Lists.newArrayList();
        
        if (Boolean.parseBoolean(filterIsFiltered)) {
            Notice filtered = new Notice();
            filtered.setTitle(filterTitle);
            filtered.getDescription().add(filterDescription);
            notices.add(filtered);
        }

        final Notice tnc = new Notice();
        tnc.setTitle(this.tncTitle);
        tnc.getDescription().add(this.tncDescription);
        tnc.getLinks().add(RdapObjectMapper.createLink(tncLinkRel, selfLink, tncLinkHref, tncLinkType));
        notices.add(tnc);

        return notices;
    }

    public List<Notice> generateObjectNotices(RpslObject rpslObject, String selfLink) {
        List<Notice> notices = Lists.newArrayList();
        Notice source = new Notice();
        source.setTitle(sourceTitle);
        source.getDescription().add(sourceDescription);
        source.getDescription().add(rpslObject.getValueForAttribute(AttributeType.SOURCE).toString());
        notices.add(source);
        return notices;
    }

    public List<Notice> generateHelpNotices(String selfUrl) {
        List<Notice> notices = Lists.newArrayList();
        Notice authNotice = new Notice();
        authNotice.setTitle(helpTitle);
        authNotice.getDescription().add(helpDescription);
        authNotice.getLinks().add(RdapObjectMapper.createLink(helpLinkRel, selfUrl, helpLinkHref, helpLinkType));
        notices.add(authNotice);
        return notices;
    }
}
