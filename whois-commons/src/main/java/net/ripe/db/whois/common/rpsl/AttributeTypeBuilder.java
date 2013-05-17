package net.ripe.db.whois.common.rpsl;

import java.util.Map;
import java.util.Set;

public interface AttributeTypeBuilder extends Documented {
    static Map<Enum, AttributeTypeBuilder> implementationMap = (System.getProperty("whois.config","").equals("apnic")) ?
        new net.apnic.db.whois.common.rpsl.AttributeTypeBuilderImpl(null,null,null).getAttributeTypeBuilderMap() :
        new AttributeTypeBuilderImpl(null,null,null).getAttributeTypeBuilderMap();

    public enum Enum {
        ABUSE_MAILBOX,
        ABUSE_C,
        ADDRESS,
        ADMIN_C,
        AGGR_BNDRY,
        AGGR_MTD,
        ALIAS,
        ASSIGNMENT_SIZE,
        AS_BLOCK,
        AS_NAME,
        AS_SET,
        AUTH,
        AUTHOR,
        AUT_NUM,
        CERTIF,
        CHANGED,
        COMPONENTS,
        COUNTRY,
        DEFAULT,
        DESCR,
        DOMAIN,
        DS_RDATA,
        ENCRYPTION,
        EXPORT,
        EXPORT_COMPS,
        E_MAIL,
        FAX_NO,
        FILTER,
        FILTER_SET,
        FINGERPR,
        FORM,
        GEOLOC,
        HOLES,
        IFADDR,
        IMPORT,
        INET6NUM,
        INETNUM,
        INET_RTR,
        INJECT,
        INTERFACE,
        IRT,
        IRT_NFY,
        KEY_CERT,
        LANGUAGE,
        LOCAL_AS,
        MBRS_BY_REF,
        MEMBERS,
        MEMBER_OF,
        METHOD,
        MNTNER,
        MNT_BY,
        MNT_DOMAINS,
        MNT_IRT,
        MNT_LOWER,
        MNT_NFY,
        MNT_REF,
        MNT_ROUTES,
        MP_DEFAULT,
        MP_EXPORT,
        MP_FILTER,
        MP_IMPORT,
        MP_MEMBERS,
        MP_PEER,
        MP_PEERING,
        NETNAME,
        NIC_HDL,
        NOTIFY,
        NSERVER,
        ORG,
        ORG_NAME,
        ORG_TYPE,
        ORGANISATION,
        ORIGIN,
        OWNER,
        PEER,
        PEERING,
        PEERING_SET,
        PERSON,
        PHONE,
        PING_HDL,
        PINGABLE,
        POEM,
        POETIC_FORM,
        REFERRAL_BY,
        REF_NFY,
        REMARKS,
        ROLE,
        ROUTE,
        ROUTE6,
        ROUTE_SET,
        RTR_SET,
        SIGNATURE,
        SOURCE,
        STATUS,
        TECH_C,
        TEXT,
        UPD_TO,
        ZONE_C
    }

    abstract String getName();

    abstract String getFlag();

    abstract Documented getDescription();

    abstract AttributeSyntax getSyntax();

    abstract AttributeValueType getValueType();

    abstract Set<ObjectType> getReferences();

    abstract Enum getEnumType();

    abstract Map<Enum, AttributeTypeBuilder> getAttributeTypeBuilderMap();
}
