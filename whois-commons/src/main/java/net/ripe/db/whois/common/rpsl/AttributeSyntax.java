package net.ripe.db.whois.common.rpsl;

import com.google.common.base.Splitter;
import net.ripe.db.whois.common.domain.Ipv4Resource;
import net.ripe.db.whois.common.domain.Ipv6Resource;
import net.ripe.db.whois.common.domain.attrs.AddressPrefixRange;
import net.ripe.db.whois.common.domain.attrs.Inet6numStatus;
import net.ripe.db.whois.common.domain.attrs.InetnumStatus;
import net.ripe.db.whois.common.domain.attrs.OrgType;
import net.ripe.db.whois.common.domain.attrs.RangeOperation;
import net.ripe.db.whois.common.generated.ComponentsParser;
import net.ripe.db.whois.common.generated.ComponentsR6Parser;
import net.ripe.db.whois.common.generated.FilterParser;
import net.ripe.db.whois.common.generated.InjectParser;
import net.ripe.db.whois.common.generated.InjectR6Parser;
import net.ripe.db.whois.common.generated.V6FilterParser;
import net.ripe.db.whois.common.profiles.WhoisConfig;

import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static net.ripe.db.whois.common.domain.CIString.ciString;

public interface AttributeSyntax extends Documented {

    static Map<AttributeSyntaxType, AttributeSyntax> implementationMap = WhoisConfig.isAPNIC() ?
            net.apnic.db.whois.common.rpsl.AttributeSyntaxImpl.getAttributeSyntaxMap() :
            net.ripe.db.whois.common.rpsl.AttributeSyntaxImpl.getAttributeSyntaxMap();

    static AttributeSyntax ANY_SYNTAX = implementationMap.get(AttributeSyntaxType.ANY_SYNTAX);
    static AttributeSyntax ADDRESS_PREFIX_RANGE_SYNTAX = implementationMap.get(AttributeSyntaxType.ADDRESS_PREFIX_RANGE_SYNTAX);
    static AttributeSyntax EMAIL_SYNTAX = implementationMap.get(AttributeSyntaxType.EMAIL_SYNTAX);
    static AttributeSyntax AGGR_BNDRY_SYNTAX = implementationMap.get(AttributeSyntaxType.AGGR_BNDRY_SYNTAX);
    static AttributeSyntax AGGR_MTD_SYNTAX = implementationMap.get(AttributeSyntaxType.AGGR_MTD_SYNTAX);
    static AttributeSyntax ALIAS_SYNTAX = implementationMap.get(AttributeSyntaxType.ALIAS_SYNTAX);
    static AttributeSyntax NUMBER_SYNTAX = implementationMap.get(AttributeSyntaxType.NUMBER_SYNTAX);
    static AttributeSyntax AS_BLOCK_SYNTAX = implementationMap.get(AttributeSyntaxType.AS_BLOCK_SYNTAX);
    static AttributeSyntax AS_SET_SYNTAX = implementationMap.get(AttributeSyntaxType.AS_SET_SYNTAX);
    static AttributeSyntax AUTH_SCHEME_SYNTAX = implementationMap.get(AttributeSyntaxType.AUTH_SCHEME_SYNTAX);
    static AttributeSyntax NIC_HANDLE_SYNTAX = implementationMap.get(AttributeSyntaxType.NIC_HANDLE_SYNTAX);
    static AttributeSyntax CERTIF_SYNTAX = implementationMap.get(AttributeSyntaxType.CERTIF_SYNTAX);
    static AttributeSyntax CHANGED_SYNTAX = implementationMap.get(AttributeSyntaxType.CHANGED_SYNTAX);
    static AttributeSyntax COMPONENTS_SYNTAX = implementationMap.get(AttributeSyntaxType.COMPONENTS_SYNTAX);
    static AttributeSyntax COUNTRY_CODE_SYNTAX = implementationMap.get(AttributeSyntaxType.COUNTRY_CODE_SYNTAX);
    static AttributeSyntax DEFAULT_SYNTAX = implementationMap.get(AttributeSyntaxType.DEFAULT_SYNTAX);
    static AttributeSyntax FREE_FORM_SYNTAX = implementationMap.get(AttributeSyntaxType.FREE_FORM_SYNTAX);
    static AttributeSyntax DOMAIN_SYNTAX = implementationMap.get(AttributeSyntaxType.DOMAIN_SYNTAX);
    static AttributeSyntax DS_RDATA_SYNTAX = implementationMap.get(AttributeSyntaxType.DS_RDATA_SYNTAX);
    static AttributeSyntax EXPORT_SYNTAX = implementationMap.get(AttributeSyntaxType.EXPORT_SYNTAX);
    static AttributeSyntax EXPORT_COMPS_SYNTAX = implementationMap.get(AttributeSyntaxType.EXPORT_COMPS_SYNTAX);
    static AttributeSyntax PHONE_SYNTAX = implementationMap.get(AttributeSyntaxType.PHONE_SYNTAX);
    static AttributeSyntax FILTER_SYNTAX = implementationMap.get(AttributeSyntaxType.FILTER_SYNTAX);
    static AttributeSyntax FILTER_SET_SYNTAX = implementationMap.get(AttributeSyntaxType.FILTER_SET_SYNTAX);
    static AttributeSyntax GENERATED_SYNTAX = implementationMap.get(AttributeSyntaxType.GENERATED_SYNTAX);
    static AttributeSyntax POETIC_FORM_SYNTAX = implementationMap.get(AttributeSyntaxType.POETIC_FORM_SYNTAX);
    static AttributeSyntax GEOLOC_SYNTAX = implementationMap.get(AttributeSyntaxType.GEOLOC_SYNTAX);
    static AttributeSyntax HOLES_SYNTAX = implementationMap.get(AttributeSyntaxType.HOLES_SYNTAX);
    static AttributeSyntax IFADDR_SYNTAX = implementationMap.get(AttributeSyntaxType.IFADDR_SYNTAX);
    static AttributeSyntax IMPORT_SYNTAX = implementationMap.get(AttributeSyntaxType.IMPORT_SYNTAX);
    static AttributeSyntax IPV6_SYNTAX = implementationMap.get(AttributeSyntaxType.IPV6_SYNTAX);
    static AttributeSyntax IPV4_SYNTAX = implementationMap.get(AttributeSyntaxType.IPV4_SYNTAX);
    static AttributeSyntax INET_RTR_SYNTAX = implementationMap.get(AttributeSyntaxType.INET_RTR_SYNTAX);
    static AttributeSyntax INJECT_SYNTAX = implementationMap.get(AttributeSyntaxType.INJECT_SYNTAX);
    static AttributeSyntax INTERFACE_SYNTAX = implementationMap.get(AttributeSyntaxType.INTERFACE_SYNTAX);
    static AttributeSyntax KEY_CERT_SYNTAX = implementationMap.get(AttributeSyntaxType.KEY_CERT_SYNTAX);
    static AttributeSyntax LANGUAGE_CODE_SYNTAX = implementationMap.get(AttributeSyntaxType.LANGUAGE_CODE_SYNTAX);
    static AttributeSyntax AS_NUMBER_SYNTAX = implementationMap.get(AttributeSyntaxType.AS_NUMBER_SYNTAX);
    static AttributeSyntax MBRS_BY_REF_SYNTAX = implementationMap.get(AttributeSyntaxType.MBRS_BY_REF_SYNTAX);
    static AttributeSyntax MEMBERS_SYNTAX = implementationMap.get(AttributeSyntaxType.MEMBERS_SYNTAX);
    static AttributeSyntax MEMBER_OF_SYNTAX = implementationMap.get(AttributeSyntaxType.MEMBER_OF_SYNTAX);
    static AttributeSyntax METHOD_SYNTAX = implementationMap.get(AttributeSyntaxType.METHOD_SYNTAX);
    static AttributeSyntax OBJECT_NAME_SYNTAX = implementationMap.get(AttributeSyntaxType.OBJECT_NAME_SYNTAX);
    static AttributeSyntax IRT_SYNTAX = implementationMap.get(AttributeSyntaxType.IRT_SYNTAX);
    static AttributeSyntax MNT_ROUTES_SYNTAX = implementationMap.get(AttributeSyntaxType.MNT_ROUTES_SYNTAX);
    static AttributeSyntax MP_DEFAULT_SYNTAX = implementationMap.get(AttributeSyntaxType.MP_DEFAULT_SYNTAX);
    static AttributeSyntax MP_EXPORT_SYNTAX = implementationMap.get(AttributeSyntaxType.MP_EXPORT_SYNTAX);
    static AttributeSyntax MP_FILTER_SYNTAX = implementationMap.get(AttributeSyntaxType.MP_FILTER_SYNTAX);
    static AttributeSyntax MP_IMPORT_SYNTAX = implementationMap.get(AttributeSyntaxType.MP_IMPORT_SYNTAX);
    static AttributeSyntax MP_MEMBERS_SYNTAX = implementationMap.get(AttributeSyntaxType.MP_MEMBERS_SYNTAX);
    static AttributeSyntax MP_PEER_SYNTAX = implementationMap.get(AttributeSyntaxType.MP_PEER_SYNTAX);
    static AttributeSyntax MP_PEERING_SYNTAX = implementationMap.get(AttributeSyntaxType.MP_PEERING_SYNTAX);
    static AttributeSyntax NETNAME_SYNTAX = implementationMap.get(AttributeSyntaxType.NETNAME_SYNTAX);
    static AttributeSyntax NSERVER_SYNTAX = implementationMap.get(AttributeSyntaxType.NSERVER_SYNTAX);
    static AttributeSyntax ORGANISATION_SYNTAX = implementationMap.get(AttributeSyntaxType.ORGANISATION_SYNTAX);
    static AttributeSyntax ORG_NAME_SYNTAX = implementationMap.get(AttributeSyntaxType.ORG_NAME_SYNTAX);
    static AttributeSyntax ORG_TYPE_SYNTAX = implementationMap.get(AttributeSyntaxType.ORG_TYPE_SYNTAX);
    static AttributeSyntax PEER_SYNTAX = implementationMap.get(AttributeSyntaxType.PEER_SYNTAX);
    static AttributeSyntax PEERING_SYNTAX = implementationMap.get(AttributeSyntaxType.PEERING_SYNTAX);
    static AttributeSyntax PEERING_SET_SYNTAX = implementationMap.get(AttributeSyntaxType.PEERING_SET_SYNTAX);
    static AttributeSyntax PERSON_ROLE_NAME_SYNTAX = implementationMap.get(AttributeSyntaxType.PERSON_ROLE_NAME_SYNTAX);
    static AttributeSyntax PINGABLE_SYNTAX = implementationMap.get(AttributeSyntaxType.PINGABLE_SYNTAX);
    static AttributeSyntax POEM_SYNTAX = implementationMap.get(AttributeSyntaxType.POEM_SYNTAX);
    static AttributeSyntax ROUTE_SYNTAX = implementationMap.get(AttributeSyntaxType.ROUTE_SYNTAX);
    static AttributeSyntax ROUTE6_SYNTAX = implementationMap.get(AttributeSyntaxType.ROUTE6_SYNTAX);
    static AttributeSyntax ROUTE_SET_SYNTAX = implementationMap.get(AttributeSyntaxType.ROUTE_SET_SYNTAX);
    static AttributeSyntax RTR_SET_SYNTAX = implementationMap.get(AttributeSyntaxType.RTR_SET_SYNTAX);
    static AttributeSyntax SOURCE_SYNTAX = implementationMap.get(AttributeSyntaxType.SOURCE_SYNTAX);
    static AttributeSyntax STATUS_SYNTAX = implementationMap.get(AttributeSyntaxType.STATUS_SYNTAX);

    boolean matches(ObjectType objectType, String value);

    static class AnySyntax implements AttributeSyntax {
        private final String description;

        public AnySyntax() {
            this("");
        }

        public AnySyntax(final String description) {
            this.description = description;
        }

        @Override
        public boolean matches(final ObjectType objectType, final String value) {
            return true;
        }

        @Override
        public String getDescription(final ObjectType objectType) {
            return description;
        }


    }

    static class AttributeSyntaxRegexp implements AttributeSyntax {
        private final Integer maxLength;
        private final Pattern matchPattern;
        private final String description;

        public AttributeSyntaxRegexp(final Pattern matchPattern, final String description) {
            this(null, matchPattern, description);
        }

        public AttributeSyntaxRegexp(final Integer maxLength, final Pattern matchPattern, final String description) {
            this.maxLength = maxLength;
            this.matchPattern = matchPattern;
            this.description = description;

        }

        @Override
        public boolean matches(final ObjectType objectType, final String value) {
            final boolean lengthOk = maxLength == null || value.length() <= maxLength;
            final boolean matches = matchPattern.matcher(value).matches();

            return lengthOk && matches;
        }

        @Override
        public String getDescription(final ObjectType objectType) {
            return description;
        }
    }

    static class RoutePrefixSyntax implements AttributeSyntax {
        @Override
        public boolean matches(final ObjectType objectType, final String value) {
            switch (objectType) {
                case ROUTE:
                    return IPV4_SYNTAX.matches(objectType, value);
                case ROUTE6:
                    return IPV6_SYNTAX.matches(objectType, value);
                default:
                    return false;
            }
        }

        @Override
        public String getDescription(final ObjectType objectType) {
            switch (objectType) {
                case ROUTE:
                    return "" +
                            "An address prefix is represented as an IPv4 address followed\n" +
                            "by the character slash \"/\" followed by an integer in the\n" +
                            "range from 0 to 32.  The following are valid address\n" +
                            "prefixes: 128.9.128.5/32, 128.9.0.0/16, 0.0.0.0/0; and the\n" +
                            "following address prefixes are invalid: 0/0, 128.9/16 since\n" +
                            "0 or 128.9 are not strings containing four integers.";
                case ROUTE6:
                    return "" +
                            "<ipv6-address>/<prefix>";
                default:
                    return "";
            }
        }
    }

    static class GeolocSyntax  implements AttributeSyntax {
        private static final Pattern GEOLOC_PATTERN = Pattern.compile("^[+-]?(\\d*\\.?\\d+)\\s+[+-]?(\\d*\\.?\\d+)$");

        private static final double LATITUDE_RANGE = 90.0;
        private static final double LONGITUDE_RANGE = 180.0;

        @Override
        public boolean matches(final ObjectType objectType, final String value) {
            final Matcher matcher = GEOLOC_PATTERN.matcher(value);
            if (!matcher.matches()) {
                return false;
            }

            if (Double.compare(LATITUDE_RANGE, Double.parseDouble(matcher.group(1))) < 0) {
                return false;
            }

            if (Double.compare(LONGITUDE_RANGE, Double.parseDouble(matcher.group(2))) < 0) {
                return false;
            }

            return true;
        }

        @Override
        public String getDescription(final ObjectType objectType) {
            return "" +
                    "Location coordinates of the resource. Can take one of the following forms:\n" +
                    "\n" +
                    "[-90,90][-180,180]\n";
        }
    }

    static class MemberOfSyntax implements AttributeSyntax {
        @Override
        public boolean matches(final ObjectType objectType, final String value) {
            switch (objectType) {
                case AUT_NUM:
                    return AS_SET_SYNTAX.matches(objectType, value);
                case ROUTE:
                case ROUTE6:
                    return ROUTE_SET_SYNTAX.matches(objectType, value);
                case INET_RTR:
                    return RTR_SET_SYNTAX.matches(objectType, value);
                default:
                    return false;
            }
        }

        @Override
        public String getDescription(final ObjectType objectType) {
            switch (objectType) {
                case AUT_NUM:
                    return "" +
                            "An as-set name is made up of letters, digits, the\n" +
                            "character underscore \"_\", and the character hyphen \"-\"; it\n" +
                            "must start with \"as-\", and the last character of a name must\n" +
                            "be a letter or a digit.\n" +
                            "\n" +
                            "An as-set name can also be hierarchical.  A hierarchical set\n" +
                            "name is a sequence of set names and AS numbers separated by\n" +
                            "colons \":\".  At least one component of such a name must be\n" +
                            "an actual set name (i.e. start with \"as-\").  All the set\n" +
                            "name components of a hierarchical as-name have to be as-set\n" +
                            "names.\n";

                case ROUTE:
                    return "" +
                            "An route-set name is made up of letters, digits, the\n" +
                            "character underscore \"_\", and the character hyphen \"-\"; it\n" +
                            "must start with \"rs-\", and the last character of a name must\n" +
                            "be a letter or a digit.\n" +
                            "\n" +
                            "A route-set name can also be hierarchical.  A hierarchical\n" +
                            "set name is a sequence of set names and AS numbers separated\n" +
                            "by colons \":\".  At least one component of such a name must\n" +
                            "be an actual set name (i.e. start with \"rs-\").  All the set\n" +
                            "name components of a hierarchical route-name have to be\n" +
                            "route-set names.\n";

                case ROUTE6:
                    return "" +
                            "An route-set name is made up of letters, digits, the\n" +
                            "character underscore \"_\", and the character hyphen \"-\"; it\n" +
                            "must start with \"rs-\", and the last character of a name must\n" +
                            "be a letter or a digit.\n" +
                            "\n" +
                            "A route-set name can also be hierarchical.  A hierarchical\n" +
                            "set name is a sequence of set names and AS numbers separated\n" +
                            "by colons \":\".  At least one component of such a name must\n" +
                            "be an actual set name (i.e. start with \"rs-\").  All the set\n" +
                            "name components of a hierarchical route-name have to be\n" +
                            "route-set names.\n";

                case INET_RTR:
                    return "" +
                            "A router-set name is made up of letters, digits, the\n" +
                            "character underscore \"_\", and the character hyphen \"-\"; it\n" +
                            "must start with \"rtrs-\", and the last character of a name\n" +
                            "must be a letter or a digit.\n" +
                            "\n" +
                            "A router-set name can also be hierarchical.  A hierarchical\n" +
                            "set name is a sequence of set names and AS numbers separated\n" +
                            "by colons \":\".  At least one component of such a name must\n" +
                            "be an actual set name (i.e. start with \"rtrs-\").  All the\n" +
                            "set name components of a hierarchical router-set name have\n" +
                            "to be router-set names.\n";
                default:
                    return "";
            }
        }
    }

    static class MembersSyntax implements AttributeSyntax {
        private final boolean allowIpv6;

        public MembersSyntax(final boolean allowIpv6) {
            this.allowIpv6 = allowIpv6;
        }

        @Override
        public boolean matches(final ObjectType objectType, final String value) {
            switch (objectType) {
                case AS_SET:
                    final boolean asNumberSyntax = AS_NUMBER_SYNTAX.matches(objectType, value);
                    final boolean asSetSyntax = AS_SET_SYNTAX.matches(objectType, value);

                    return asNumberSyntax || asSetSyntax;

                case ROUTE_SET:
                    if (ROUTE_SET_SYNTAX.matches(objectType, value)) {
                        return true;
                    }

                    if (AS_NUMBER_SYNTAX.matches(objectType, value) || AS_SET_SYNTAX.matches(objectType, value)) {
                        return true;
                    }

                    if (ADDRESS_PREFIX_RANGE_SYNTAX.matches(objectType, value)) {
                        final AddressPrefixRange apr = AddressPrefixRange.parse(value);
                        if ((apr.getIpInterval() instanceof Ipv4Resource) || (allowIpv6 && apr.getIpInterval() instanceof Ipv6Resource)) {
                            return true;
                        }
                    }

                    return validateRouteSetWithRange(objectType, value);

                case RTR_SET:
                    if (allowIpv6 && IPV6_SYNTAX.matches(objectType, value)) {
                        return true;
                    }

                    return INET_RTR_SYNTAX.matches(objectType, value) || RTR_SET_SYNTAX.matches(objectType, value) || IPV4_SYNTAX.matches(objectType, value);
                default:
                    return false;
            }
        }

        @Override
        public String getDescription(final ObjectType objectType) {
            switch (objectType) {
                case AS_SET:
                    return "" +
                            "list of\n" +
                            "<as-number> or\n" +
                            "<as-set-name>\n";
                case ROUTE_SET:
                    return "" +
                            "list of\n" +
                            "<address-prefix-range> or\n" +
                            "<route-set-name> or\n" +
                            "<route-set-name><range-operator>.\n";

                case RTR_SET:
                    return allowIpv6 ? "" +
                            "list of\n" +
                            "<inet-rtr-name> or\n" +
                            "<rtr-set-name> or\n" +
                            "<ipv4-address> or\n" +
                            "<ipv6-address>\n"
                            : "" +
                            "list of\n" +
                            "<inet-rtr-name> or\n" +
                            "<rtr-set-name> or\n" +
                            "<ipv4-address>\n";

                default:
                    return "";
            }
        }

        private boolean validateRouteSetWithRange(ObjectType objectType, String value) {
            final int rangeOperationIdx = value.lastIndexOf('^');
            if (rangeOperationIdx == -1) {
                return false;
            }

            final String routeSet = value.substring(0, rangeOperationIdx);
            final boolean routeSetSyntaxResult = ROUTE_SET_SYNTAX.matches(objectType, routeSet);
            if (!routeSetSyntaxResult) {
                return routeSetSyntaxResult;
            }

            final String rangeOperation = value.substring(rangeOperationIdx);
            try {
                RangeOperation.parse(rangeOperation, 0, 128);
                return true;
            } catch (IllegalArgumentException e) {
                return false;
            }
        }
    }


    class OrgTypeSyntax implements AttributeSyntax {
        @Override
        public boolean matches(final ObjectType objectType, final String value) {
            return OrgType.getFor(value) != null;
        }

        @Override
        public String getDescription(final ObjectType objectType) { // TODO [AK] Generate possible values from OrgType
            return "" +
                    "org-type can have one of these values:\n" +
                    "\n" +
                    "o IANA\n" +
                    "o RIR\n" +
                    "o NIR (There are no NIRs in the RIPE NCC service region.)\n" +
                    "o LIR\n" +
                    "o WHITEPAGES\n" +
                    "o DIRECT_ASSIGNMENT\n" +
                    "o OTHER\n" +
                    "\n" +
                    "    'IANA' for Internet Assigned Numbers Authority\n" +
                    "    'RIR' for Regional Internet Registries\n" +
                    "    'NIR' for National Internet Registries\n" +
                    "    'LIR' for Local Internet Registries\n" +
                    "    'WHITEPAGES' for special links to industry people\n" +
                    "    'DIRECT_ASSIGNMENT' for direct contract with RIPE NCC\n" +
                    "    'OTHER' for all other organisations.\n";
        }
    }

    static class PersonRoleSyntax implements AttributeSyntax {
        private static final Pattern PATTERN = Pattern.compile("(?i)^[A-Z][A-Z0-9\\\\.`'_-]{0,63}(?: [A-Z0-9\\\\.`'_-]{1,64}){0,9}$");
        private static final Splitter SPLITTER = Splitter.on(' ').trimResults().omitEmptyStrings();

        @Override
        public boolean matches(final ObjectType objectType, final String value) {
            if (!PATTERN.matcher(value).matches()) {
                return false;
            }

            int nrNamesStartingWithLetter = 0;
            for (final String name : SPLITTER.split(value)) {
                if (Character.isLetter(name.charAt(0))) {
                    nrNamesStartingWithLetter++;

                    if (nrNamesStartingWithLetter == 2) {
                        return true;
                    }
                }
            }

            return false;
        }

        @Override
        public String getDescription(final ObjectType objectType) {
            return "" +
                    "A list of at least 2 words separated by white space. The\n" +
                    "first and the last word cannot end with dot (\".\"). The\n" +
                    "following words are not allowed: \"Dr\", \"Prof\", \"Mv\", \"Ms\",\n" +
                    "\"Mr\", no matter whether they end with dot (\".\") or not. A\n" +
                    "word is made up of letters, digits, the character underscore\n" +
                    "\"_\", and the character hyphen \"-\"; the first character of a\n" +
                    "name must be a letter, and the last character of a name must\n" +
                    "be a letter or a digit.\n";

        }
    }

    static class StatusSyntax implements AttributeSyntax {
        @Override
        public boolean matches(final ObjectType objectType, final String value) {
            switch (objectType) {
                case INETNUM:
                    try {
                        InetnumStatus.getStatusFor(ciString(value));
                        return true;
                    } catch (IllegalArgumentException ignored) {
                        return false;
                    }
                case INET6NUM:
                    try {
                        Inet6numStatus.getStatusFor(ciString(value));
                        return true;
                    } catch (IllegalArgumentException ignored) {
                        return false;
                    }
                default:
                    return false;
            }
        }

        @Override
        public String getDescription(final ObjectType objectType) {
            final StringBuilder descriptionBuilder = new StringBuilder();
            descriptionBuilder.append("Status can have one of these values:\n\n");

            switch (objectType) {
                case INETNUM:
                    for (final InetnumStatus status : InetnumStatus.values()) {
                        descriptionBuilder.append("o ").append(status).append('\n');
                    }

                    return descriptionBuilder.toString();
                case INET6NUM:
                    for (final Inet6numStatus status : Inet6numStatus.values()) {
                        descriptionBuilder.append("o ").append(status).append('\n');
                    }

                    return descriptionBuilder.toString();
                default:
                    return "";
            }
        }
    }

    static class ComponentsSyntax implements AttributeSyntax {
        @Override
        public boolean matches(final ObjectType objectType, final String value) {
            switch (objectType) {
                case ROUTE:
                    return new AttributeSyntaxParser(new ComponentsParser()).matches(objectType, value);
                case ROUTE6:
                    return new AttributeSyntaxParser(new ComponentsR6Parser()).matches(objectType, value);
                default:
                    return false;
            }
        }

        @Override
        public String getDescription(final ObjectType objectType) {
            return "" +
                    "[ATOMIC] [[<filter>] [protocol <protocol> <filter> ...]]\n" +
                    "\n" +
                    "<protocol> is a routing routing protocol name such as\n" +
                    "BGP4, OSPF or RIP\n" +
                    "\n" +
                    "<filter> is a policy expression\n";
        }
    }

    static class ExportCompsSyntax implements AttributeSyntax {
        @Override
        public boolean matches(final ObjectType objectType, final String value) {
            switch (objectType) {
                case ROUTE:
                    return new AttributeSyntaxParser(new FilterParser()).matches(objectType, value);
                case ROUTE6:
                    return new AttributeSyntaxParser(new V6FilterParser()).matches(objectType, value);
                default:
                    return false;
            }
        }

        @Override
        public String getDescription(final ObjectType objectType) {
            switch (objectType) {
                case ROUTE:
                    return "" +
                            "Logical expression which when applied to a set of routes\n" +
                            "returns a subset of these routes. Please refer to RFC 2622\n" +
                            "for more information.";
                case ROUTE6:
                    return "" +
                            "Logical expression which when applied to a set of routes\n" +
                            "returns a subset of these routes. Please refer to RFC 2622\n" +
                            "and RPSLng I-D for more information.";
                default:
                    return "";
            }
        }
    }

    static class InjectSyntax implements AttributeSyntax {
        @Override
        public boolean matches(final ObjectType objectType, final String value) {
            switch (objectType) {
                case ROUTE:
                    return new AttributeSyntaxParser(new InjectParser()).matches(objectType, value);

                case ROUTE6:
                    return new AttributeSyntaxParser(new InjectR6Parser()).matches(objectType, value);

                default:
                    return false;
            }
        }

        @Override
        public String getDescription(final ObjectType objectType) {
            return "" +
                    "[at <router-expression>]\n" +
                    "[action <action>]\n" +
                    "[upon <condition>]\n";
        }
    }

    static class AttributeSyntaxParser implements AttributeSyntax {
        private final AttributeParser attributeParser;
        private final Documented description;

        public AttributeSyntaxParser(final AttributeParser attributeParser) {
            this(attributeParser, "");
        }

        public AttributeSyntaxParser(final AttributeParser attributeParser, final String description) {
            this(attributeParser, new Single(description));
        }

        public AttributeSyntaxParser(final AttributeParser attributeParser, final Documented description) {
            this.attributeParser = attributeParser;
            this.description = description;
        }

        @Override
        public boolean matches(final ObjectType objectType, final String value) {
            try {
                attributeParser.parse(value);
                return true;
            } catch (IllegalArgumentException ignored) {
                return false;
            }
        }

        @Override
        public String getDescription(final ObjectType objectType) {
            return description.getDescription(objectType);
        }
    }

    enum AttributeSyntaxType {
        ANY_SYNTAX,
        ADDRESS_PREFIX_RANGE_SYNTAX,
        EMAIL_SYNTAX,
        AGGR_BNDRY_SYNTAX,
        AGGR_MTD_SYNTAX,
        ALIAS_SYNTAX,
        NUMBER_SYNTAX,
        AS_BLOCK_SYNTAX,
        AS_SET_SYNTAX,
        AUTH_SCHEME_SYNTAX,
        NIC_HANDLE_SYNTAX,
        CERTIF_SYNTAX,
        CHANGED_SYNTAX,
        COMPONENTS_SYNTAX,
        COUNTRY_CODE_SYNTAX,
        DEFAULT_SYNTAX,
        FREE_FORM_SYNTAX,
        DOMAIN_SYNTAX,
        DS_RDATA_SYNTAX,
        EXPORT_SYNTAX,
        EXPORT_COMPS_SYNTAX,
        PHONE_SYNTAX,
        FILTER_SYNTAX,
        FILTER_SET_SYNTAX,
        GENERATED_SYNTAX,
        POETIC_FORM_SYNTAX,
        GEOLOC_SYNTAX,
        HOLES_SYNTAX,
        IFADDR_SYNTAX,
        IMPORT_SYNTAX,
        IPV6_SYNTAX,
        IPV4_SYNTAX,
        INET_RTR_SYNTAX,
        INJECT_SYNTAX,
        INTERFACE_SYNTAX,
        KEY_CERT_SYNTAX,
        LANGUAGE_CODE_SYNTAX,
        AS_NUMBER_SYNTAX,
        MBRS_BY_REF_SYNTAX,
        MEMBERS_SYNTAX,
        MEMBER_OF_SYNTAX,
        METHOD_SYNTAX,
        OBJECT_NAME_SYNTAX,
        IRT_SYNTAX,
        MNT_ROUTES_SYNTAX,
        MP_DEFAULT_SYNTAX,
        MP_EXPORT_SYNTAX,
        MP_FILTER_SYNTAX,
        MP_IMPORT_SYNTAX,
        MP_MEMBERS_SYNTAX,
        MP_PEER_SYNTAX,
        MP_PEERING_SYNTAX,
        NETNAME_SYNTAX,
        NSERVER_SYNTAX,
        ORGANISATION_SYNTAX,
        ORG_NAME_SYNTAX,
        ORG_TYPE_SYNTAX,
        PEER_SYNTAX,
        PEERING_SYNTAX,
        PEERING_SET_SYNTAX,
        PERSON_ROLE_NAME_SYNTAX,
        PINGABLE_SYNTAX,
        POEM_SYNTAX,
        ROUTE_SYNTAX,
        ROUTE6_SYNTAX,
        ROUTE_SET_SYNTAX,
        RTR_SET_SYNTAX,
        SOURCE_SYNTAX,
        STATUS_SYNTAX;
    }
}
