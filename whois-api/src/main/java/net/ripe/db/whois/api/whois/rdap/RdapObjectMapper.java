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
import org.joda.time.LocalDateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

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
import static net.ripe.db.whois.common.rpsl.AttributeType.LANGUAGE;
import static net.ripe.db.whois.common.rpsl.AttributeType.NETNAME;
import static net.ripe.db.whois.common.rpsl.AttributeType.NSERVER;
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

class RdapObjectMapper {
    private static final Logger LOGGER = LoggerFactory.getLogger(RdapObjectMapper.class);

    protected static final List<String> RDAP_CONFORMANCE_LEVEL = Lists.newArrayList("rdap_level_0");

    protected static DatatypeFactory dtf;
    static {
        try {
            dtf = DatatypeFactory.newInstance();
        } catch (DatatypeConfigurationException dtfe) {
            LOGGER.error("Could not instantiate DatatypeFactory");
        }
    }

    private static final Map<AttributeType, String> CONTACT_ATTRIBUTE_TO_ROLE_NAME = Maps.newHashMap();

    static {
        CONTACT_ATTRIBUTE_TO_ROLE_NAME.put(ADMIN_C, "administrative");
        CONTACT_ATTRIBUTE_TO_ROLE_NAME.put(TECH_C, "technical");
        CONTACT_ATTRIBUTE_TO_ROLE_NAME.put(ZONE_C, "zone");
    }

    @Value("${rdap.public.port43:whois.ripe.net}")
    private static String port43;

    public static Object map(
            final String requestUrl,
            final String baseUrl,
            final RpslObject rpslObject,
            final List<RpslObject> relatedObjects,
            final LocalDateTime lastChangedTimestamp,
            final List<RpslObject> abuseContacts,
            final RpslObject parentRpslObject) {

        RdapObject rdapResponse;
        final ObjectType rpslObjectType = rpslObject.getType();

        switch (rpslObjectType) {
            case DOMAIN:
                rdapResponse = createDomain(rpslObject, requestUrl, baseUrl);
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
            // TODO: [RL] Configuration (property?) for allowed RPSL object types for entity lookups
            // TODO: [ES] Denis to review
            case ORGANISATION:
            case IRT:
                rdapResponse = createEntity(rpslObject, requestUrl, baseUrl);
                break;
            default:
                throw new IllegalArgumentException("Unhandled object type: " + rpslObject.getType());
        }

        rdapResponse.getRdapConformance().addAll(RDAP_CONFORMANCE_LEVEL);
        rdapResponse.setPort43(port43);
        rdapResponse.getNotices().addAll(NoticeFactory.generateNotices(rpslObject, requestUrl));

        final List<Remark> remarks = createRemarks(rpslObject);
        if (!remarks.isEmpty()) {
            rdapResponse.getRemarks().addAll(remarks);
        }
        rdapResponse.getEvents().add(createEvent(lastChangedTimestamp));

        for (final RpslObject abuseContact : abuseContacts) {
            rdapResponse.getEntities().add(createEntity(abuseContact, requestUrl, baseUrl));
        }
        List<Entity> ctcEntities = contactEntities(rpslObject, relatedObjects, requestUrl, baseUrl);
        if (!ctcEntities.isEmpty()) {
            rdapResponse.getEntities().addAll(ctcEntities);
        }

        return rdapResponse;
    }

    private static Ip createIp(final RpslObject rpslObject, final RpslObject parentRpslObject, final String requestUrl, final String baseUrl) {
        final Ip ip = new Ip();
        ip.setHandle(rpslObject.getKey().toString());
        IpInterval ipInterval;
        if (rpslObject.getType() == INET6NUM) {
            ipInterval = Ipv6Resource.parse(rpslObject.getKey());
            ip.setIpVersion("v6");
        } else {
            ipInterval = Ipv4Resource.parse(rpslObject.getKey());
            ip.setIpVersion("v4");
        }

        String selfUrl = baseUrl + "/ip/" + ipInterval.toString();

        // TODO: find a better way to remove the cidr notation
        String startAddr = IpInterval.asIpInterval(ipInterval.beginAsInetAddress()).toString();
        String endAddr = IpInterval.asIpInterval(ipInterval.endAsInetAddress()).toString();
        ip.setStartAddress(startAddr.split("/")[0]);
        ip.setEndAddress(endAddr.split("/")[0]);

        ip.setName(rpslObject.getValueForAttribute(NETNAME).toString());
        ip.setCountry(rpslObject.getValueForAttribute(COUNTRY).toString());
        ip.setLang(rpslObject.getValuesForAttribute(LANGUAGE).isEmpty() ? null : Joiner.on(",").join(rpslObject.getValuesForAttribute(LANGUAGE)));
        ip.setType(rpslObject.getValueForAttribute(STATUS).toString());

        if (parentRpslObject != null) {
            ip.setParentHandle(parentRpslObject.getValueForAttribute(NETNAME).toString());

            CIString parentKey = parentRpslObject.getKey();
            IpInterval parentInterval = (parentRpslObject.getType() == INET6NUM) ? Ipv6Resource.parse(parentKey) : Ipv4Resource.parse(parentKey);
            ip.getLinks().add(createLink("up", selfUrl, baseUrl + "/ip/" + parentInterval.toString()));
        }

        ip.getLinks().add(createLink("self", requestUrl, selfUrl));

        return ip;
    }

    private static List<Remark> createRemarks(final RpslObject rpslObject) {
        final List<Remark> remarkList = Lists.newArrayList();

        final List<String> descriptions = Lists.newArrayList();

        for (final CIString description : rpslObject.getValuesForAttribute(DESCR)) {
            descriptions.add(description.toString());
        }

        if (!descriptions.isEmpty()) {
            Remark remark = new Remark();
            remark.setTitle("description");
            remark.getDescription().addAll(descriptions);
            remarkList.add(remark);
        }

        final List<String> remarks = Lists.newArrayList();

        for (final CIString description : rpslObject.getValuesForAttribute(REMARKS)) {
            remarks.add(description.toString());
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

    private static List<Entity> contactEntities(final RpslObject rpslObject, List<RpslObject> relatedObjects, final String requestUrl, final String baseUrl) {
        final List<Entity> entities = Lists.newArrayList();

        final Map<CIString, RpslObject> relatedObjectMap = Maps.newHashMap();

        for (final RpslObject object : relatedObjects) {
            relatedObjectMap.put(object.getKey(), object);
        }

        final Map<CIString, Set<AttributeType>> contacts = Maps.newTreeMap();

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
                entity = createEntity(contactRpslObject, requestUrl, baseUrl);

                final List<Remark> remarks = createRemarks(contactRpslObject);
                if (!remarks.isEmpty()) {
                    entity.getRemarks().addAll(remarks);
                }
            } else {
                entity = new Entity();
                entity.setHandle(entry.getKey().toString());
            }
            for (final AttributeType attributeType : entry.getValue()) {
                entity.getRoles().add(CONTACT_ATTRIBUTE_TO_ROLE_NAME.get(attributeType));
            }
            entities.add(entity);
        }

        return entities;
    }

    private static Entity createEntity(final RpslObject rpslObject, final String requestUrl, final String baseUrl) {
        final Entity entity = new Entity();
        entity.setHandle(rpslObject.getKey().toString());
        setVCardArray(entity,createVCard(rpslObject));

        final String selfUrl = baseUrl + "/entity/" + entity.getHandle();
        entity.getLinks().add(createLink("self", requestUrl, selfUrl));

        return entity;
    }

    private static Autnum createAutnumResponse(final RpslObject rpslObject, String requestUrl, String baseUrl) {
        final Autnum autnum = new Autnum();
        final String keyValue = rpslObject.getKey().toString();
        autnum.setHandle(keyValue);

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
            autnum.setType("DIRECT ALLOCATION");

            final String selfUrl = baseUrl + "/autnum/" + autNum.getValue();
            autnum.getLinks().add(createLink("self", requestUrl, selfUrl));
        }


        return autnum;
    }

    private static Domain createDomain(final RpslObject rpslObject, String requestUrl, String baseUrl) {
        final Domain domain = new Domain();
        domain.setHandle(rpslObject.getKey().toString());
        domain.setLdhName(rpslObject.getKey().toString());

        final String selfUrl = baseUrl + "/domain/" + domain.getHandle();
        domain.getLinks().add(createLink("self", requestUrl, selfUrl));

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
                for (final RpslAttribute attribute : rpslObject.findAttributes(PERSON)) {
                    builder.addFn(attribute.getCleanValue().toString());
                }
                builder.addKind("individual");
                break;
            case ORGANISATION:
                for (final RpslAttribute attribute : rpslObject.findAttributes(ORG_NAME)) {
                    builder.addFn(attribute.getCleanValue().toString());
                }
                builder.addKind("org");
                break;
            case ROLE:
                for (final RpslAttribute attribute : rpslObject.findAttributes(ROLE)) {
                    builder.addFn(attribute.getCleanValue().toString());
                }
                builder.addKind("group");
                break;
            case IRT:
                for (final RpslAttribute attribute : rpslObject.findAttributes(IRT)) {
                    builder.addFn(attribute.getCleanValue().toString());
                }
                builder.addKind("group");
                break;
            default:
                break;
        }

        List<CIString> addrList = new ArrayList<CIString>();
        for (final CIString address : rpslObject.getValuesForAttribute(ADDRESS)) {
            addrList.add(address);
        }
        if (!addrList.isEmpty()) {
            String addr = Joiner.on("\n").join(addrList.listIterator());
            List<String> emptyAddrList = Arrays.asList("", "", "", "", "", "", "");
            builder.addAdr(VCardHelper.createMap(Maps.immutableEntry("type", "work"), Maps.immutableEntry("label", addr)), emptyAddrList);
        }

        for (final CIString phone : rpslObject.getValuesForAttribute(PHONE)) {
            builder.addTel(VCardHelper.createMap(Maps.immutableEntry("type", Lists.newArrayList("work", "voice"))),phone.toString());
        }

        for (final CIString fax : rpslObject.getValuesForAttribute(FAX_NO)) {
            builder.addTel(VCardHelper.createMap(Maps.immutableEntry("type", "work")),fax.toString());
        }

        for (final CIString email : rpslObject.getValuesForAttribute(E_MAIL)) {
            // TODO ?? Is it valid to have more than 1 email
            builder.addEmail(VCardHelper.createMap(Maps.immutableEntry("type", "work")),email.toString());
        }

        for (final CIString org : rpslObject.getValuesForAttribute(ORG)) {
            builder.addOrg(org.toString());
        }

        for (final CIString geoloc : rpslObject.getValuesForAttribute(GEOLOC)) {
            builder.addGeo(VCardHelper.createMap(Maps.immutableEntry("type", "work")), geoloc.toString());
        }

        return builder.build();
    }

    public static XMLGregorianCalendar convertToXMLGregorianCalendar(final LocalDateTime lastChanged) {
        GregorianCalendar gc =  new GregorianCalendar();
        gc.setTimeInMillis(lastChanged.toDateTime().getMillis());
        return dtf.newXMLGregorianCalendar(gc);
    }

    public static Link createLink(String rel, String value, String href) {
        Link link = new Link();
        link.setRel(rel);
        link.setValue(value);
        link.setHref(href);
        return link;
    }

    public static void setVCardArray(Entity entity, final VCard... vCards) {
        List<Object> vcardArray = entity.getVcardArray();
        vcardArray.add("vcard");
        for (VCard next : vCards) {
            vcardArray.add(next.getValues());
        }
    }
}
