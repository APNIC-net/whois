package net.ripe.db.whois.common.rpsl;

import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import net.ripe.db.whois.common.domain.CIString;

import javax.annotation.CheckForNull;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static net.ripe.db.whois.common.domain.CIString.ciString;
import static net.ripe.db.whois.common.rpsl.AttributeValueType.LIST_VALUE;

public enum AttributeType implements AttributeTypeBuilder {
    ABUSE_MAILBOX(AttributeTypeBuilder.implementationMap.get(Enum.ABUSE_MAILBOX)),
    ABUSE_C(AttributeTypeBuilder.implementationMap.get(Enum.ABUSE_C)),
    ADDRESS(AttributeTypeBuilder.implementationMap.get(Enum.ADDRESS)),
    ADMIN_C(AttributeTypeBuilder.implementationMap.get(Enum.ADMIN_C)),
    AGGR_BNDRY(AttributeTypeBuilder.implementationMap.get(Enum.AGGR_BNDRY)),
    AGGR_MTD(AttributeTypeBuilder.implementationMap.get(Enum.AGGR_MTD)),
    ALIAS(AttributeTypeBuilder.implementationMap.get(Enum.ALIAS)),
    ASSIGNMENT_SIZE(AttributeTypeBuilder.implementationMap.get(Enum.ASSIGNMENT_SIZE)),
    AS_BLOCK(AttributeTypeBuilder.implementationMap.get(Enum.AS_BLOCK)),
    AS_NAME(AttributeTypeBuilder.implementationMap.get(Enum.AS_NAME)),
    AS_SET(AttributeTypeBuilder.implementationMap.get(Enum.AS_SET)),
    AUTH(AttributeTypeBuilder.implementationMap.get(Enum.AUTH)),
    AUTHOR(AttributeTypeBuilder.implementationMap.get(Enum.AUTHOR)),
    AUT_NUM(AttributeTypeBuilder.implementationMap.get(Enum.AUT_NUM)),
    CERTIF(AttributeTypeBuilder.implementationMap.get(Enum.CERTIF)),
    CHANGED(AttributeTypeBuilder.implementationMap.get(Enum.CHANGED)),
    COMPONENTS(AttributeTypeBuilder.implementationMap.get(Enum.COMPONENTS)),
    COUNTRY(AttributeTypeBuilder.implementationMap.get(Enum.COUNTRY)),
    DEFAULT(AttributeTypeBuilder.implementationMap.get(Enum.DEFAULT)),
    DESCR(AttributeTypeBuilder.implementationMap.get(Enum.DESCR)),
    DOMAIN(AttributeTypeBuilder.implementationMap.get(Enum.DOMAIN)),
    DS_RDATA(AttributeTypeBuilder.implementationMap.get(Enum.DS_RDATA)),
    ENCRYPTION(AttributeTypeBuilder.implementationMap.get(Enum.ENCRYPTION)),
    EXPORT(AttributeTypeBuilder.implementationMap.get(Enum.EXPORT)),
    EXPORT_COMPS(AttributeTypeBuilder.implementationMap.get(Enum.EXPORT_COMPS)),
    E_MAIL(AttributeTypeBuilder.implementationMap.get(Enum.E_MAIL)),
    FAX_NO(AttributeTypeBuilder.implementationMap.get(Enum.FAX_NO)),
    FILTER(AttributeTypeBuilder.implementationMap.get(Enum.FILTER)),
    FILTER_SET(AttributeTypeBuilder.implementationMap.get(Enum.FILTER_SET)),
    FINGERPR(AttributeTypeBuilder.implementationMap.get(Enum.FINGERPR)),
    FORM(AttributeTypeBuilder.implementationMap.get(Enum.FORM)),
    GEOLOC(AttributeTypeBuilder.implementationMap.get(Enum.GEOLOC)),
    HOLES(AttributeTypeBuilder.implementationMap.get(Enum.HOLES)),
    IFADDR(AttributeTypeBuilder.implementationMap.get(Enum.IFADDR)),
    IMPORT(AttributeTypeBuilder.implementationMap.get(Enum.IMPORT)),
    INET6NUM(AttributeTypeBuilder.implementationMap.get(Enum.INET6NUM)),
    INETNUM(AttributeTypeBuilder.implementationMap.get(Enum.INETNUM)),
    INET_RTR(AttributeTypeBuilder.implementationMap.get(Enum.INET_RTR)),
    INJECT(AttributeTypeBuilder.implementationMap.get(Enum.INJECT)),
    INTERFACE(AttributeTypeBuilder.implementationMap.get(Enum.INTERFACE)),
    IRT(AttributeTypeBuilder.implementationMap.get(Enum.IRT)),
    IRT_NFY(AttributeTypeBuilder.implementationMap.get(Enum.IRT_NFY)),
    KEY_CERT(AttributeTypeBuilder.implementationMap.get(Enum.KEY_CERT)),
    LANGUAGE(AttributeTypeBuilder.implementationMap.get(Enum.LANGUAGE)),
    LOCAL_AS(AttributeTypeBuilder.implementationMap.get(Enum.LOCAL_AS)),
    MBRS_BY_REF(AttributeTypeBuilder.implementationMap.get(Enum.MBRS_BY_REF)),
    MEMBERS(AttributeTypeBuilder.implementationMap.get(Enum.MEMBERS)),
    MEMBER_OF(AttributeTypeBuilder.implementationMap.get(Enum.MEMBER_OF)),
    METHOD(AttributeTypeBuilder.implementationMap.get(Enum.METHOD)),
    MNTNER(AttributeTypeBuilder.implementationMap.get(Enum.MNTNER)),
    MNT_BY(AttributeTypeBuilder.implementationMap.get(Enum.MNT_BY)),
    MNT_DOMAINS(AttributeTypeBuilder.implementationMap.get(Enum.MNT_DOMAINS)),
    MNT_IRT(AttributeTypeBuilder.implementationMap.get(Enum.MNT_IRT)),
    MNT_LOWER(AttributeTypeBuilder.implementationMap.get(Enum.MNT_LOWER)),
    MNT_NFY(AttributeTypeBuilder.implementationMap.get(Enum.MNT_NFY)),
    MNT_REF(AttributeTypeBuilder.implementationMap.get(Enum.MNT_REF)),
    MNT_ROUTES(AttributeTypeBuilder.implementationMap.get(Enum.MNT_ROUTES)),
    MP_DEFAULT(AttributeTypeBuilder.implementationMap.get(Enum.MP_DEFAULT)),
    MP_EXPORT(AttributeTypeBuilder.implementationMap.get(Enum.MP_EXPORT)),
    MP_FILTER(AttributeTypeBuilder.implementationMap.get(Enum.MP_FILTER)),
    MP_IMPORT(AttributeTypeBuilder.implementationMap.get(Enum.MP_IMPORT)),
    MP_MEMBERS(AttributeTypeBuilder.implementationMap.get(Enum.MP_MEMBERS)),
    MP_PEER(AttributeTypeBuilder.implementationMap.get(Enum.MP_PEER)),
    MP_PEERING(AttributeTypeBuilder.implementationMap.get(Enum.MP_PEERING)),
    NETNAME(AttributeTypeBuilder.implementationMap.get(Enum.NETNAME)),
    NIC_HDL(AttributeTypeBuilder.implementationMap.get(Enum.NIC_HDL)),
    NOTIFY(AttributeTypeBuilder.implementationMap.get(Enum.NOTIFY)),
    NSERVER(AttributeTypeBuilder.implementationMap.get(Enum.NSERVER)),
    ORG(AttributeTypeBuilder.implementationMap.get(Enum.ORG)),
    ORG_NAME(AttributeTypeBuilder.implementationMap.get(Enum.ORG_NAME)),
    ORG_TYPE(AttributeTypeBuilder.implementationMap.get(Enum.ORG_TYPE)),
    ORGANISATION(AttributeTypeBuilder.implementationMap.get(Enum.ORGANISATION)),
    ORIGIN(AttributeTypeBuilder.implementationMap.get(Enum.ORIGIN)),
    OWNER(AttributeTypeBuilder.implementationMap.get(Enum.OWNER)),
    PEER(AttributeTypeBuilder.implementationMap.get(Enum.PEER)),
    PEERING(AttributeTypeBuilder.implementationMap.get(Enum.PEERING)),
    PEERING_SET(AttributeTypeBuilder.implementationMap.get(Enum.PEERING_SET)),
    PERSON(AttributeTypeBuilder.implementationMap.get(Enum.PERSON)),
    PHONE(AttributeTypeBuilder.implementationMap.get(Enum.PHONE)),
    PING_HDL(AttributeTypeBuilder.implementationMap.get(Enum.PING_HDL)),
    PINGABLE(AttributeTypeBuilder.implementationMap.get(Enum.PINGABLE)),
    POEM(AttributeTypeBuilder.implementationMap.get(Enum.POEM)),
    POETIC_FORM(AttributeTypeBuilder.implementationMap.get(Enum.POETIC_FORM)),
    REFERRAL_BY(AttributeTypeBuilder.implementationMap.get(Enum.REFERRAL_BY)),
    REF_NFY(AttributeTypeBuilder.implementationMap.get(Enum.REF_NFY)),
    REMARKS(AttributeTypeBuilder.implementationMap.get(Enum.REMARKS)),
    ROLE(AttributeTypeBuilder.implementationMap.get(Enum.ROLE)),
    ROUTE(AttributeTypeBuilder.implementationMap.get(Enum.ROUTE)),
    ROUTE6(AttributeTypeBuilder.implementationMap.get(Enum.ROUTE6)),
    ROUTE_SET(AttributeTypeBuilder.implementationMap.get(Enum.ROUTE_SET)),
    RTR_SET(AttributeTypeBuilder.implementationMap.get(Enum.RTR_SET)),
    SIGNATURE(AttributeTypeBuilder.implementationMap.get(Enum.SIGNATURE)),
    SOURCE(AttributeTypeBuilder.implementationMap.get(Enum.SOURCE)),
    STATUS(AttributeTypeBuilder.implementationMap.get(Enum.STATUS)),
    TECH_C(AttributeTypeBuilder.implementationMap.get(Enum.TECH_C)),
    TEXT(AttributeTypeBuilder.implementationMap.get(Enum.TEXT)),
    UPD_TO(AttributeTypeBuilder.implementationMap.get(Enum.UPD_TO)),
    ZONE_C(AttributeTypeBuilder.implementationMap.get(Enum.ZONE_C)),

    // APNIC
    ADDRESS_PREFIX_RANGE(AttributeTypeBuilder.implementationMap.get(Enum.APNIC_ADDRESS_PREFIX_RANGE)),
    APNIC_DOM_NET(AttributeTypeBuilder.implementationMap.get(Enum.APNIC_DOM_NET)),
    APNIC_REGISTRY_NAME(AttributeTypeBuilder.implementationMap.get(Enum.APNIC_REGISTRY_NAME)),
    APNIC_SUBDOMAIN_NAME(AttributeTypeBuilder.implementationMap.get(Enum.APNIC_SUBDOMAIN_NAME));
    // APNIC_LIMERICK(AttributeTypeBuilder.implementationMap.get(Enum.APNIC_LIMERICK)),
    // APNIC_MEMBERS_AS(AttributeTypeBuilder.implementationMap.get(Enum.APNIC_MEMBERS_AS)),
    // APNIC_REFER(AttributeTypeBuilder.implementationMap.get(Enum.APNIC_REFER)),


    private static final Map<CIString, AttributeType> TYPE_NAMES = Maps.newHashMapWithExpectedSize(AttributeType.values().length);

    private static List<AttributeType> implementedValues = Lists.newArrayList();

    static {
        for (final AttributeType type : AttributeType.values()) {
            if (type.isImplemented()) {
                TYPE_NAMES.put(ciString(type.getName()), type);
                TYPE_NAMES.put(ciString(type.getFlag()), type);
                implementedValues.add(type);
            }
        }
    }

    private final AttributeTypeBuilder attributeTypeBuilder;

    private AttributeType(final AttributeTypeBuilder attributeTypeBuilderImpl) {
        this.attributeTypeBuilder = attributeTypeBuilderImpl;
    }

    public static AttributeType getByName(final String name) throws IllegalArgumentException {
        final AttributeType attributeType = getByNameOrNull(name);
        if (attributeType == null) {
            throw new IllegalArgumentException("Attribute type " + name + " not found");
        }

        return attributeType;
    }

    @CheckForNull
    public static AttributeType getByNameOrNull(final String name) {
        String nameOrNull = name;
        if (nameOrNull.length() == 3 && nameOrNull.charAt(0) == '*') {
            nameOrNull = nameOrNull.substring(1);
        }

        return TYPE_NAMES.get(ciString(nameOrNull));
    }

    public String getName() {
        return attributeTypeBuilder.getName();
    }

    public String getFlag() {
        return attributeTypeBuilder.getFlag();
    }

    boolean isListValue() {
        return attributeTypeBuilder.getValueType().equals(LIST_VALUE);
    }

    public AttributeSyntax getSyntax() {
        return attributeTypeBuilder.getSyntax();
    }

    public boolean isValidValue(final ObjectType objectType, final CIString value) {
        return isValidValue(objectType, value.toString());
    }

    public boolean isValidValue(final ObjectType objectType, final String value) {
        return attributeTypeBuilder.getSyntax().matches(objectType, value);
    }

    Iterable<String> splitValue(final String value) {
        return attributeTypeBuilder.getValueType().getValues(value);
    }

    public Set<ObjectType> getReferences() {
        return attributeTypeBuilder.getReferences();
    }

    public Set<ObjectType> getReferences(final CIString value) {
        if (this == AUTH && value.startsWith(ciString("MD5-PW"))) {
            return Collections.emptySet();
        }

        return attributeTypeBuilder.getReferences();
    }

    public Documented getDescription() {
        return attributeTypeBuilder.getDescription();
    }

    public AttributeValueType getValueType() {
        return attributeTypeBuilder.getValueType();
    }

    public Enum getEnumType() {
        return attributeTypeBuilder.getEnumType();
    }

    public Map<Enum, AttributeTypeBuilder> getAttributeTypeBuilderMap() {
        return attributeTypeBuilder.getAttributeTypeBuilderMap();
    }

    @Override
    public String getDescription(final ObjectType objectType) {
        return attributeTypeBuilder.getDescription(objectType);
    }

    public boolean isImplemented() {
        return attributeTypeBuilder != null;
    }

    public static List<AttributeType> implementedValues() {
       return implementedValues;
    }
}
