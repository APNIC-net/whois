package net.ripe.db.whois.api.whois.rdap;

import com.google.common.base.Joiner;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import net.ripe.db.whois.api.whois.rdap.domain.Autnum;
import net.ripe.db.whois.api.whois.rdap.domain.Domain;
import net.ripe.db.whois.api.whois.rdap.domain.Entity;
import net.ripe.db.whois.api.whois.rdap.domain.Event;
import net.ripe.db.whois.api.whois.rdap.domain.Ip;
import net.ripe.db.whois.api.whois.rdap.domain.Link;
import net.ripe.db.whois.api.whois.rdap.domain.Nameserver;
import net.ripe.db.whois.api.whois.rdap.domain.RdapObject;
import net.ripe.db.whois.api.whois.rdap.domain.Remark;
import net.ripe.db.whois.api.whois.rdap.domain.Role;
import net.ripe.db.whois.api.whois.rdap.domain.SearchResult;
import net.ripe.db.whois.api.whois.rdap.domain.vcard.VCard;
import net.ripe.db.whois.common.domain.CIString;
import net.ripe.db.whois.common.domain.IpInterval;
import net.ripe.db.whois.common.domain.Ipv4Resource;
import net.ripe.db.whois.common.domain.Ipv6Resource;
import net.ripe.db.whois.common.domain.attrs.AsBlockRange;
import net.ripe.db.whois.common.domain.attrs.AutNum;
import net.ripe.db.whois.common.domain.attrs.DsRdata;
import net.ripe.db.whois.common.domain.attrs.NServer;
import net.ripe.db.whois.common.rpsl.AttributeType;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.RpslAttribute;
import net.ripe.db.whois.common.rpsl.RpslObject;
import org.eclipse.jetty.util.URIUtil;
import org.joda.time.LocalDateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Collections;

import static net.ripe.db.whois.common.rpsl.AttributeType.ABUSE_MAILBOX;
import static net.ripe.db.whois.common.rpsl.AttributeType.ADDRESS;
import static net.ripe.db.whois.common.rpsl.AttributeType.ADMIN_C;
import static net.ripe.db.whois.common.rpsl.AttributeType.AS_NAME;
import static net.ripe.db.whois.common.rpsl.AttributeType.COUNTRY;
import static net.ripe.db.whois.common.rpsl.AttributeType.DESCR;
import static net.ripe.db.whois.common.rpsl.AttributeType.DS_RDATA;
import static net.ripe.db.whois.common.rpsl.AttributeType.E_MAIL;
import static net.ripe.db.whois.common.rpsl.AttributeType.FAX_NO;
import static net.ripe.db.whois.common.rpsl.AttributeType.GEOLOC;
import static net.ripe.db.whois.common.rpsl.AttributeType.IRT;
import static net.ripe.db.whois.common.rpsl.AttributeType.MNT_IRT;
import static net.ripe.db.whois.common.rpsl.AttributeType.NETNAME;
import static net.ripe.db.whois.common.rpsl.AttributeType.ORG;
import static net.ripe.db.whois.common.rpsl.AttributeType.ORG_NAME;
import static net.ripe.db.whois.common.rpsl.AttributeType.PERSON;
import static net.ripe.db.whois.common.rpsl.AttributeType.PHONE;
import static net.ripe.db.whois.common.rpsl.AttributeType.REMARKS;
import static net.ripe.db.whois.common.rpsl.AttributeType.ROLE;
import static net.ripe.db.whois.common.rpsl.AttributeType.STATUS;
import static net.ripe.db.whois.common.rpsl.AttributeType.TECH_C;
import static net.ripe.db.whois.common.rpsl.AttributeType.ZONE_C;
import static net.ripe.db.whois.common.rpsl.ObjectType.INET6NUM;
import static net.ripe.db.whois.common.rpsl.ObjectType.DOMAIN;

class RdapObjectMapper {
    private static final Logger LOGGER = LoggerFactory.getLogger(RdapObjectMapper.class);

    protected static final List<String> RDAP_CONFORMANCE_LEVEL = Lists.newArrayList("rdap_level_0");
    private static final Joiner NEWLINE_JOINER = Joiner.on("\n");
    private final String port43 = "port43";

    protected static DatatypeFactory dtf;
    static {
        try {
            dtf = DatatypeFactory.newInstance();
        } catch (DatatypeConfigurationException dtfe) {
            LOGGER.error("Could not instantiate DatatypeFactory");
        }
    }

    private static final Map<AttributeType, Role> CONTACT_ATTRIBUTE_TO_ROLE_NAME = Maps.newHashMap();
    static {
        CONTACT_ATTRIBUTE_TO_ROLE_NAME.put(ADMIN_C, Role.ADMINISTRATIVE);
        CONTACT_ATTRIBUTE_TO_ROLE_NAME.put(TECH_C, Role.TECHNICAL);
        CONTACT_ATTRIBUTE_TO_ROLE_NAME.put(MNT_IRT, Role.ABUSE);
        CONTACT_ATTRIBUTE_TO_ROLE_NAME.put(ZONE_C, Role.TECHNICAL);
    }

    public static RdapObject map(
            final String requestUrl,
            final String baseUrl,
            final RpslObject rpslObject,
            final List<RpslObject> relatedObjects,
            final LocalDateTime lastChangedTimestamp,
            final List<RpslObject> abuseContacts,
            final RpslObject parentRpslObject,
            final String port43,
            final NoticeFactory noticeFactory) {
        RdapObject rdapResponse = getRdapObject(requestUrl, baseUrl, rpslObject, relatedObjects, lastChangedTimestamp, abuseContacts, parentRpslObject, noticeFactory);
        addInformational(baseUrl, rpslObject, relatedObjects, lastChangedTimestamp, abuseContacts, parentRpslObject, port43, rdapResponse, requestUrl, noticeFactory);
        return rdapResponse;
    }

    private static RdapObject getRdapObject(final String requestUrl, 
                                            final String baseUrl,
                                            final RpslObject rpslObject, 
                                            final List<RpslObject> relatedObjects,
                                            final LocalDateTime lastChangedTimestamp, 
                                            final List<RpslObject> abuseContacts,
                                            final RpslObject parentRpslObject,
                                            final NoticeFactory noticeFactory) {
        RdapObject rdapResponse;
        final ObjectType rpslObjectType = rpslObject.getType();

        switch (rpslObjectType) {
            case DOMAIN:
                rdapResponse = createDomain(rpslObject, baseUrl);
                break;
            case AUT_NUM:
            case AS_BLOCK:
                rdapResponse = createAutnumResponse(rpslObject, requestUrl, baseUrl);
                break;
            case INETNUM:
            case INET6NUM:
                rdapResponse = createIp(rpslObject, parentRpslObject, requestUrl, baseUrl);
                break;
            case PERSON:
            case ROLE:
            case ORGANISATION:
            case IRT:
                rdapResponse = createEntity(rpslObject, null, baseUrl);
                break;
            default:
                throw new IllegalArgumentException("Unhandled object type: " + rpslObject.getType());
        }

        rdapResponse.getEvents().add(createEvent(lastChangedTimestamp));

        /* todo: This shouldn't be null. The check should only be here
         * temporarily. */
        if (noticeFactory != null) {
            rdapResponse.getNotices().addAll(noticeFactory.generateObjectNotices(rpslObject, requestUrl));
        }

        return rdapResponse;
    }

    public static RdapObject mapSearch(final String objectType,
                                       final String requestUrl,
                                       final String baseUrl,
                                       final List<RpslObject> objects, 
                                       final Iterable<LocalDateTime> localDateTimes,
                                       final NoticeFactory noticeFactory) {
        final SearchResult searchResult = new SearchResult();
        searchResult.isForType(objectType);
        final Iterator<LocalDateTime> iterator = localDateTimes.iterator();

        for (final RpslObject object : objects) {
            if (object.getType() == DOMAIN) {
                searchResult.addDomainSearchResult((Domain) getRdapObject(requestUrl, baseUrl, object, new ArrayList<RpslObject>(), iterator.next(), Collections.EMPTY_LIST, null, noticeFactory));
            } else {
                searchResult.addEntitySearchResult((Entity) getRdapObject(requestUrl, baseUrl, object, new ArrayList<RpslObject>(), iterator.next(), Collections.EMPTY_LIST, null, noticeFactory));
            }
        }

        searchResult.getRdapConformance().addAll(RDAP_CONFORMANCE_LEVEL);
        searchResult.getNotices().addAll(noticeFactory.generateResponseNotices(requestUrl));

        return searchResult;
    }

    private static void addInformational(String baseUrl, RpslObject rpslObject, List<RpslObject> relatedObjects, LocalDateTime lastChangedTimestamp, List<RpslObject> abuseContacts, RpslObject parentRpslObject, String port43, RdapObject rdapResponse, String requestUrl, NoticeFactory noticeFactory) {
        rdapResponse.getRdapConformance().addAll(RDAP_CONFORMANCE_LEVEL);
        final String selfUrl = getSelfUrl(rdapResponse, requestUrl);

        /* todo: This shouldn't be null. The check should only be here
         * temporarily. */
        if (noticeFactory != null) {
            rdapResponse.getNotices().addAll(noticeFactory.generateResponseNotices(requestUrl));
        }

        final List<Remark> remarks = createRemarks(rpslObject);
        if (!remarks.isEmpty()) {
            rdapResponse.getRemarks().addAll(remarks);
        }
        /* todo: This is added in getRdapObject, and it appears as though
         * addInformational is not called independently of getRdapObject, so
         * presumably getRdapObject is the correct place for it (doesn't make
         * sense to add it twice). */
        //rdapResponse.getEvents().add(createEvent(lastChangedTimestamp));

        for (final RpslObject abuseContact : abuseContacts) {
            final Entity entity = createEntity(abuseContact, selfUrl, baseUrl);
            entity.getRoles().add(Role.ABUSE);
            rdapResponse.getEntities().add(entity);
        }
        List<Entity> ctcEntities = contactEntities(rpslObject, relatedObjects, selfUrl, baseUrl);
        if (!ctcEntities.isEmpty()) {
            rdapResponse.getEntities().addAll(ctcEntities);
        }

        rdapResponse.setPort43(port43);
    }

    private static Ip createIp(final RpslObject rpslObject, final RpslObject parentRpslObject, final String requestUrl, final String baseUrl) {
        final Ip ip = new Ip();
        final IpInterval ipInterval = IpInterval.parse(rpslObject.getKey());
        ip.setHandle(rpslObject.getKey().toString());
        ip.setIpVersion(rpslObject.getType() == INET6NUM ? "v6" : "v4");

        final String selfUrl = String.format("%s/%s/%s",baseUrl,Ip.class.getSimpleName().toLowerCase(),urlencode(ipInterval.toString()));

        // TODO: find a better way to remove the cidr notation
        String startAddr = IpInterval.asIpInterval(ipInterval.beginAsInetAddress()).toString();
        String endAddr = IpInterval.asIpInterval(ipInterval.endAsInetAddress()).toString();
        ip.setStartAddress(startAddr.split("/")[0]);
        ip.setEndAddress(endAddr.split("/")[0]);

        ip.setName(rpslObject.getValueForAttribute(NETNAME).toString());
        ip.setCountry(rpslObject.getValueForAttribute(COUNTRY).toString());
        ip.setType(rpslObject.getValueForAttribute(STATUS).toString());

        if (parentRpslObject != null) {
            ip.setParentHandle(parentRpslObject.getKey().toString());

            CIString parentKey = parentRpslObject.getKey();
            IpInterval parentInterval = (parentRpslObject.getType() == INET6NUM) ? Ipv6Resource.parse(parentKey) : Ipv4Resource.parse(parentKey);

            final String parentUrl = String.format("%s/%s/%s",baseUrl,Ip.class.getSimpleName().toLowerCase(),urlencode(parentInterval));
            ip.getLinks().add(createLink("up", selfUrl, parentUrl));
        }

        ip.getLinks().add(createLink("self", selfUrl, selfUrl));

        return ip;
    }

    private static List<Remark> createRemarks(final RpslObject rpslObject) {
        final List<Remark> remarkList = Lists.newArrayList();

        final List<String> descriptions = Lists.newArrayList();

        for (final RpslAttribute attribute : rpslObject.findAttributes(DESCR)) {
            for (final CIString description : attribute.getCleanValues() ) {
                descriptions.add(description.toString());
            }
        }

        if (!descriptions.isEmpty()) {
            Remark remark = new Remark();
            remark.setTitle("description");
            remark.getDescription().addAll(descriptions);
            remarkList.add(remark);
        }

        final List<String> remarks = Lists.newArrayList();

        for (final RpslAttribute attribute : rpslObject.findAttributes(REMARKS)) {
            for (final CIString remark : attribute.getCleanValues() ) {
                remarks.add(remark.toString());
            }
        }

        if (!remarks.isEmpty()) {
            Remark remark = new Remark();
            remark.setTitle("remarks");
            remark.getDescription().addAll(remarks);
            remarkList.add(remark);
        }

        return remarkList;
    }

    private static Event createEvent(final LocalDateTime lastChanged) {
        final Event lastChangedEvent = new Event();
        lastChangedEvent.setEventAction("last changed");
        lastChangedEvent.setEventDate(convertToXMLGregorianCalendar(lastChanged));
        return lastChangedEvent;
    }

    private static List<Entity> contactEntities(final RpslObject rpslObject, List<RpslObject> relatedObjects, final String topUrl, final String baseUrl) {
        final List<Entity> entities = Lists.newArrayList();
        final Map<CIString, Set<AttributeType>> contacts = Maps.newTreeMap();

        final Map<CIString, RpslObject> relatedObjectMap = Maps.newHashMap();

        for (final RpslObject object : relatedObjects) {
            relatedObjectMap.put(object.getKey(), object);
        }

        for (final AttributeType attributeType : CONTACT_ATTRIBUTE_TO_ROLE_NAME.keySet()) {
            for (final RpslAttribute attribute : rpslObject.findAttributes(attributeType)) {
                final CIString contactName = attribute.getCleanValue();
                if (contacts.containsKey(contactName)) {
                    contacts.get(contactName).add(attribute.getType());
                } else {
                    contacts.put(contactName, Sets.newHashSet(attribute.getType()));
                }
            }
        }

        for (final Map.Entry<CIString, Set<AttributeType>> entry : contacts.entrySet()) {
            final Entity entity;
            if (relatedObjectMap.containsKey(entry.getKey())) {
                final RpslObject contactRpslObject = relatedObjectMap.get(entry.getKey());
                entity = createEntity(contactRpslObject, topUrl, baseUrl);

                final List<Remark> remarks = createRemarks(contactRpslObject);
                if (!remarks.isEmpty()) {
                    entity.getRemarks().addAll(remarks);
                }
            } else {
                entity = new Entity();
                entity.setHandle(entry.getKey().toString());
            }
            for (final AttributeType attributeType : entry.getValue()) {
                final List<Role> roles = entity.getRoles();
                final Role role = CONTACT_ATTRIBUTE_TO_ROLE_NAME.get(attributeType);
                if (!roles.contains(role)) {
                    roles.add(role);
                }
            }
            entities.add(entity);
        }

        return entities;
    }

    private static Entity createEntity(final RpslObject rpslObject, final String topUrl, final String baseUrl) {
        final Entity entity = new Entity();
        entity.setHandle(rpslObject.getKey().toString());
        setVCardArray(entity,createVCard(rpslObject));

        final String selfUrl = String.format("%s/%s/%s",baseUrl,Entity.class.getSimpleName().toLowerCase(),urlencode(entity.getHandle()));
        entity.getLinks().add(createLink("self", topUrl != null ? topUrl : selfUrl, selfUrl));

        return entity;
    }

    private static Autnum createAutnumResponse(final RpslObject rpslObject, final String requestUrl, final String baseUrl) {
        final Autnum autnum = new Autnum();
        final String keyValue = rpslObject.getKey().toString();
        autnum.setHandle(keyValue);
        if (rpslObject.containsAttribute(COUNTRY)) {
            autnum.setCountry(rpslObject.getValueForAttribute(COUNTRY).toString());
        }

        if (rpslObject.getType() == ObjectType.AS_BLOCK) {
            final AsBlockRange asBlockRange = AsBlockRange.parse(keyValue);
            autnum.setStartAutnum(asBlockRange.getBegin());
            autnum.setEndAutnum(asBlockRange.getEnd());
            autnum.setName(keyValue);

            // TODO: [RL] What's the canonical self url for a block? Punt for now and just use what they requested
            autnum.getLinks().add(createLink("self", requestUrl, requestUrl));
        } else {
            final AutNum autNum = AutNum.parse(keyValue);
            autnum.setStartAutnum(autNum.getValue());
            autnum.setEndAutnum(autNum.getValue());
            autnum.setName(rpslObject.getValueForAttribute(AS_NAME).toString().replace(" ", ""));

            final String selfUrl = String.format("%s/%s/%s",baseUrl,AutNum.class.getSimpleName().toLowerCase(),urlencode(autNum.getValue()));
            autnum.getLinks().add(createLink("self", selfUrl, selfUrl));
        }


        return autnum;
    }

    private static Domain createDomain(final RpslObject rpslObject, String baseUrl) {
        final Domain domain = new Domain();
        domain.setHandle(rpslObject.getKey().toString());
        domain.setLdhName(rpslObject.getKey().toString());

        final String selfUrl = String.format("%s/%s/%s",baseUrl,Domain.class.getSimpleName().toLowerCase(),urlencode(domain.getHandle()));
        domain.getLinks().add(createLink("self", selfUrl, selfUrl));

        final Map<CIString, Set<IpInterval>> hostnameMap = new HashMap<>();

        for (final CIString nserverValue : rpslObject.getValuesForAttribute(AttributeType.NSERVER)) {
            final NServer nserver = NServer.parse(nserverValue.toString());

            final CIString hostname = nserver.getHostname();

            final Set<IpInterval> ipIntervalSet;
            if (hostnameMap.containsKey(hostname)) {
                ipIntervalSet = hostnameMap.get(hostname);
            } else {
                ipIntervalSet = Sets.newHashSet();
                hostnameMap.put(hostname, ipIntervalSet);
            }

            final IpInterval ipInterval = nserver.getIpInterval();
            if (ipInterval != null) {
                ipIntervalSet.add(ipInterval);
            }
        }

        for (final CIString hostname : hostnameMap.keySet()) {
            final Nameserver nameserver = new Nameserver();
            nameserver.setLdhName(hostname.toString());

            final Set<IpInterval> ipIntervals = hostnameMap.get(hostname);
            if (!ipIntervals.isEmpty()) {

                final Nameserver.IpAddresses ipAddresses = new Nameserver.IpAddresses();
                for (IpInterval ipInterval : ipIntervals) {
                    if (ipInterval instanceof Ipv4Resource) {
                        ipAddresses.getIpv4().add(IpInterval.asIpInterval(ipInterval.beginAsInetAddress()).toString());
                    } else if (ipInterval instanceof Ipv6Resource) {
                        ipAddresses.getIpv6().add(IpInterval.asIpInterval(ipInterval.beginAsInetAddress()).toString());
                    }
                }
                nameserver.setIpAddresses(ipAddresses);
            }

            domain.getNameServers().add(nameserver);
        }

        final Domain.SecureDNS secureDNS = new Domain.SecureDNS();
        secureDNS.setDelegationSigned(false);

        for (final CIString rdata : rpslObject.getValuesForAttribute(DS_RDATA)) {
            final DsRdata dsRdata = DsRdata.parse(rdata);

            secureDNS.setDelegationSigned(true);

            final Domain.SecureDNS.DsData dsData = new Domain.SecureDNS.DsData();
            dsData.setKeyTag(dsRdata.getKeytag());
            dsData.setAlgorithm((short)dsRdata.getAlgorithm());
            dsData.setDigestType(dsRdata.getDigestType());
            dsData.setDigest(dsRdata.getDigestHexString());

            secureDNS.getDsData().add(dsData);
        }

        if (secureDNS.isDelegationSigned()) {
            domain.setSecureDNS(secureDNS);
        }

        return domain;
    }

    private static VCard createVCard(final RpslObject rpslObject) {
        final VCardBuilder builder = new VCardBuilder();
        builder.addVersion();

        switch (rpslObject.getType()) {
            case PERSON:
                builder.addFn(rpslObject.getValueForAttribute(PERSON).toString());
                builder.addKind("individual");
                break;
            case ORGANISATION:
                builder.addFn(rpslObject.getValueForAttribute(ORG_NAME).toString());
                builder.addKind("org");
                break;
            case ROLE:
                builder.addFn(rpslObject.getValueForAttribute(ROLE).toString());
                builder.addKind("group");
                break;
            case IRT:
                builder.addFn(rpslObject.getValueForAttribute(IRT).toString());
                builder.addKind("group");
                for (final CIString email : rpslObject.getValuesForAttribute(ABUSE_MAILBOX)) {
                    builder.addEmail(VCardHelper.createMap(Maps.immutableEntry("pref", "1")), email.toString());
                }
                break;
            default:
                break;
        }

        List<CIString> addrList = new ArrayList<CIString>();
        for (final CIString address : rpslObject.getValuesForAttribute(ADDRESS)) {
            addrList.add(address);
        }
        if (!addrList.isEmpty()) {
            String addr = NEWLINE_JOINER.join(addrList.listIterator());
            List<String> emptyAddrList = Arrays.asList("", "", "", "", "", "", "");
            builder.addAdr(VCardHelper.createMap(Maps.immutableEntry("label", addr)), emptyAddrList);
        }

        for (final CIString phone : rpslObject.getValuesForAttribute(PHONE)) {
            builder.addTel(VCardHelper.createMap(Maps.immutableEntry("type", "voice")),phone.toString());
        }

        for (final CIString fax : rpslObject.getValuesForAttribute(FAX_NO)) {
            builder.addTel(VCardHelper.createMap(Maps.immutableEntry("type", "fax")), fax.toString());
        }

        for (final CIString email : rpslObject.getValuesForAttribute(E_MAIL)) {
            builder.addEmail(email.toString());
        }

        for (final CIString org : rpslObject.getValuesForAttribute(ORG)) {
            builder.addOrg(org.toString());
        }

        for (final CIString geoloc : rpslObject.getValuesForAttribute(GEOLOC)) {
            builder.addGeo(geoloc.toString());
        }

        return builder.build();
    }

    public static XMLGregorianCalendar convertToXMLGregorianCalendar(final LocalDateTime lastChanged) {
        GregorianCalendar gc =  new GregorianCalendar();
        gc.setTimeInMillis(lastChanged.toDateTime().getMillis());
        return dtf.newXMLGregorianCalendar(gc);
    }

    public static Link createLink(final String rel, final String value, final String href) {
        return createLink(rel, value, href, null);
    }

    public static Link createLink(final String rel, final String value, final String href, final String type) {
        Link link = new Link();
        link.setRel(rel);
        link.setValue(value);
        link.setHref(href);
        link.setType(type);
        return link;
    }

    public static void setVCardArray(final Entity entity, final VCard... vCards) {
        List<Object> vcardArray = entity.getVcardArray();
        vcardArray.add("vcard");
        for (VCard next : vCards) {
            vcardArray.add(next.getValues());
        }
    }

    public static String getSelfUrl(final RdapObject rdapObject, final String defaultUrl) {
        List<Link> links = rdapObject.getLinks();
        for (final Link link : links) {
            if (link.getRel().equals("self")) {
                return link.getHref();
            }
        }

        return defaultUrl;
    }

    public static String urlencode(Object obj) {
        return URIUtil.encodePath(String.valueOf(obj));
    }
}
