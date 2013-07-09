package net.ripe.db.whois.common.rpsl;

import net.ripe.db.whois.common.generated.*;
import org.springframework.beans.factory.BeanInitializationException;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

// TODO: [AH] queries should NOT match AUTO- versions of keys
// TODO: [AH] fix capture groups (add '?:' where capture is not needed)
public abstract class AttributeSyntaxImpl implements AttributeSyntax {
    static Map<AttributeSyntaxType, AttributeSyntax> attributeSyntaxTypeMap = new HashMap<AttributeSyntaxType, AttributeSyntax>();

    static {
        put(attributeSyntaxTypeMap, AttributeSyntaxType.ANY_SYNTAX, new AnySyntax());

        put(attributeSyntaxTypeMap, AttributeSyntaxType.EMAIL_SYNTAX, new AttributeSyntaxRegexp(80, Pattern.compile("(?i)^.+@([^.]+[.])+[^.]+$"),
                "An e-mail address as defined in RFC 2822.\n"));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.ADDRESS_PREFIX_RANGE_SYNTAX, new AttributeSyntaxParser(new AttributeParser.AddressPrefixRangeParser()));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.ALIAS_SYNTAX,new AttributeSyntaxRegexp(254,
                Pattern.compile("(?i)^[A-Z0-9]([-A-Z0-9]*[A-Z0-9])?(\\.[A-Z0-9]([-A-Z0-9]*[A-Z0-9])?)*(\\.)?$"), "" +
                "Domain name as specified in RFC 1034 (point 5.2.1.2) with or\n" +
                "without trailing dot (\".\").  The total length should not exceed\n" +
                "254 characters (octets).\n"));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.AS_BLOCK_SYNTAX, new AttributeSyntaxParser(new AttributeParser.AsBlockParser(), "" +
                "<as-number> - <as-number>\n"));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.AS_NUMBER_SYNTAX, new AttributeSyntaxParser(new AttributeParser.AutNumParser(), "" +
                "An \"AS\" string followed by an integer in the range\n" +
                "from 0 to 4294967295\n"));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.AS_SET_SYNTAX, new AttributeSyntaxParser(new AttributeParser.AsSetParser(), "" +
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
                "names.\n"));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.AGGR_BNDRY_SYNTAX, new AttributeSyntaxParser(new AggrBndryParser(), "" +
                "[<as-expression>]\n"));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.AGGR_MTD_SYNTAX,  new AttributeSyntaxParser(new AggrMtdParser(), "" +
                "inbound | outbound [<as-expression>]\n"));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.AUTH_SCHEME_SYNTAX, new AttributeSyntaxRegexp(
                Pattern.compile("(?i)^(MD5-PW \\$1\\$[A-Z0-9./]{1,8}\\$[A-Z0-9./]{22}|PGPKEY-[A-F0-9]{8}|X509-[1-9][0-9]{0,19}|AUTO-[1-9][0-9]*)$"), "" +
                "<auth-scheme> <scheme-info>       Description\n" +
                "\n" +
                "MD5-PW        encrypted           This scheme is the weakest form of\n" +
                "              password, produced  authentication. It is by no means\n" +
                "              using the FreeBSD   to keep out a determined malicious\n" +
                "              crypt_md5           attacker. As you are publishing the\n" +
                "              algorithm           encrypted password in the RIPE\n" +
                "                                  database, it is open to attack.\n" +
                "                                  We strongly advise phrases longer\n" +
                "                                  than 8 characters to be used,\n" +
                "                                  avoiding the use of words or\n" +
                "                                  combinations of words found in any\n" +
                "                                  dictionary of any language.\n" +
                "\n" +
                "PGPKEY-<id>                       Strong scheme of authentication.\n" +
                "                                  <id> is the PGP key ID to be\n" +
                "                                  used for authentication. This string\n" +
                "                                  is the same one that is used in the\n" +
                "                                  corresponding key-cert object's\n" +
                "                                  \"key-cert:\" attribute.\n" +
                "\n" +
                "X509-<nnn>                       Strong scheme of authentication.\n" +
                "                                  <nnn> is the index number of the\n" +
                "                                  corresponding key-cert object's\n" +
                "                                  \"key-cert:\" attribute (X509-nnn).\n"));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.CERTIF_SYNTAX,     new AnySyntax("" +
                "The value of the public key should be supplied either using\n" +
                "multiple \"certif:\" attributes, or in one \"certif:\"\n" +
                "attribute. In the first case, this is easily done by\n" +
                "exporting the key from your local key ring in ASCII armored\n" +
                "format and prepending each line of the key with the string\n" +
                "\"certif:\". In the second case, line continuation should be\n" +
                "used to represent an ASCII armored format of the key. All\n" +
                "the lines of the exported key must be included; also the\n" +
                "begin and end markers and the empty line which separates the\n" +
                "header from the key body.\n"));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.CHANGED_SYNTAX, new AttributeSyntaxParser(new AttributeParser.ChangedParser(), "" +
                "An e-mail address as defined in RFC 2822, followed by a date\n" +
                "in the format YYYYMMDD.\n"));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.COUNTRY_CODE_SYNTAX, new AttributeSyntaxRegexp(Pattern.compile("(?i)^[a-z]{2}$"),
                "Valid two-letter ISO 3166 country code."));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.COMPONENTS_SYNTAX, new ComponentsSyntax());

        put(attributeSyntaxTypeMap, AttributeSyntaxType.DEFAULT_SYNTAX,  new AttributeSyntaxParser(new DefaultParser(), "" +
                "to <peering> [action <action>] [networks <filter>]"));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.DOMAIN_SYNTAX, new AttributeSyntaxParser(new AttributeParser.DomainParser(), "" +
                "Domain name as specified in RFC 1034 (point 5.2.1.2) with or\n" +
                "without trailing dot (\".\").  The total length should not exceed\n" +
                "254 characters (octets).\n"));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.DS_RDATA_SYNTAX, new AttributeSyntaxRegexp(255,
                Pattern.compile("(?i)^([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-4])( ([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))( ([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])|RSAMD5|DH|DSA|ECC|RSASHA1|INDIRECT|PRIVATEDNS|PRIVATEOID)([ 0-9a-fA-F]{1,128})$"), "" +
                "<Keytag> | <Algorithm> | <Digest type> | <Digest> | ; <Comment>\n" +
                "\n" +
                "Keytag is represented by an unsigned decimal integer (0-65535).\n" +
                "\n" +
                "Algorithm is represented by an unsigned decimal integer (0-255) or one of the following mnemonics:\n" +
                "RSAMD5, DH, DSA, ECC, RSASHA1, INDIRECT, PRIVATEDNS, PRIVATEOID.\n" +
                "\n" +
                "Digest type may be represented by a unsigned decimal integer (0-255) and is usually 1, which stands for SHA-1.\n" +
                "\n" +
                "Digest is a digest in hexadecimal representation (case insensitive). Its length varies for various digest types.\n" +
                "For digest type SHA-1 digest is represented by 20 octets (40 characters, plus possible spaces).\n" +
                "\n" +
                "For more details, see RFC4034.\n"));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.EXPORT_COMPS_SYNTAX, new ExportCompsSyntax());

        put(attributeSyntaxTypeMap, AttributeSyntaxType.EXPORT_SYNTAX, new AttributeSyntaxParser(new ExportParser(), "" +
                "[protocol <protocol-1>] [into <protocol-1>]\n" +
                "to <peering-1> [action <action-1>]\n" +
                "    .\n" +
                "    .\n" +
                "    .\n" +
                "to <peering-N> [action <action-N>]\n" +
                "announce <filter>\n"));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.FILTER_SYNTAX, new AttributeSyntaxParser(new FilterParser(), "" +
                "Logical expression which when applied to a set of routes\n" +
                "returns a subset of these routes. Please refer to RFC 2622\n" +
                "for more information.\n"));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.FILTER_SET_SYNTAX, new AttributeSyntaxParser(new AttributeParser.FilterSetParser(), "" +
                "A filter-set name is made up of letters, digits, the\n" +
                "character underscore \"_\", and the character hyphen \"-\"; it\n" +
                "must start with \"fltr-\", and the last character of a name\n" +
                "must be a letter or a digit.\n" +
                "\n" +
                "A filter-set name can also be hierarchical.  A hierarchical\n" +
                "set name is a sequence of set names and AS numbers separated\n" +
                "by colons \":\".  At least one component of such a name must\n" +
                "be an actual set name (i.e. start with \"fltr-\").  All the\n" +
                "set name components of a hierarchical filter-name have to be\n" +
                "filter-set names.\n"));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.FREE_FORM_SYNTAX,  new AttributeSyntaxRegexp(Pattern.compile("(?s)^.*$"), "" +
                "A sequence of ASCII characters.\n"));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.GENERATED_SYNTAX, new AnySyntax("" +
                "Attribute generated by server."));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.GEOLOC_SYNTAX, new GeolocSyntax());

        put(attributeSyntaxTypeMap, AttributeSyntaxType.HOLES_SYNTAX, new RoutePrefixSyntax());

        put(attributeSyntaxTypeMap, AttributeSyntaxType.IMPORT_SYNTAX, new AttributeSyntaxParser(new ImportParser(), "" +
                "[protocol <protocol-1>] [into <protocol-1>]\n" +
                "from <peering-1> [action <action-1>]\n" +
                "    .\n" +
                "    .\n" +
                "    .\n" +
                "from <peering-N> [action <action-N>]\n" +
                "accept <filter>\n"));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.INET_RTR_SYNTAX, new AttributeSyntaxRegexp(254,
                Pattern.compile("(?i)^[A-Z0-9]([-_A-Z0-9]*[A-Z0-9])?(\\.[A-Z0-9]([-_A-Z0-9]*[A-Z0-9])?)*(\\.)?$"), "" +
                "Domain name as specified in RFC 1034 (point 5.2.1.2) with or\n" +
                "without trailing dot (\".\").  The total length should not exceed\n" +
                "254 characters (octets).\n"));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.IFADDR_SYNTAX, new AttributeSyntaxParser(new IfaddrParser(), "" +
                "<ipv4-address> masklen <integer> [action <action>]"));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.INJECT_SYNTAX, new InjectSyntax());

        put(attributeSyntaxTypeMap, AttributeSyntaxType.INTERFACE_SYNTAX, new AttributeSyntaxParser(new InterfaceParser(), "" +
                "afi <afi> <ipv4-address> masklen <integer> [action <action>]\n" +
                "afi <afi> <ipv6-address> masklen <integer> [action <action>]\n" +
                "          [tunnel <remote-endpoint-address>,<encapsulation>]\n"));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.IPV4_SYNTAX, new AttributeSyntaxParser(new AttributeParser.Ipv4ResourceParser(), "" +
                "<ipv4-address> - <ipv4-address>"));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.IPV6_SYNTAX, new AttributeSyntaxParser(new AttributeParser.Ipv6ResourceParser(), "" +
                "<ipv6-address>/<prefix>"));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.IRT_SYNTAX, new AttributeSyntaxRegexp(Pattern.compile("(?i)^irt-[A-Z0-9_-]*[A-Z0-9]$"), "" +
                "An irt name is made up of letters, digits, the character\n" +
                "underscore \"_\", and the character hyphen \"-\"; it must start\n" +
                "with \"irt-\", and the last character of a name must be a\n" +
                "letter or a digit.\n"));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.KEY_CERT_SYNTAX, new AttributeSyntaxRegexp(
                Pattern.compile("(?i)^(PGPKEY-[A-F0-9]{8})|(X509-[1-9][0-9]*)|(AUTO-[1-9][0-9]*)$"), "" +
                "PGPKEY-<id>\n" +
                "\n" +
                "<id> is  the PGP key ID of the public key in 8-digit\n" +
                "hexadecimal format without \"0x\" prefix."));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.LANGUAGE_CODE_SYNTAX,  new AttributeSyntaxRegexp(Pattern.compile("(?i)^[a-z]{2}$"), "" +
                "Valid two-letter ISO 639-1 language code.\n"));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.MBRS_BY_REF_SYNTAX,  new AnySyntax("" +
                "<mntner-name> | ANY\n"));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.MEMBER_OF_SYNTAX, new MemberOfSyntax());

        put(attributeSyntaxTypeMap, AttributeSyntaxType.MEMBERS_SYNTAX, new MembersSyntax(false));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.METHOD_SYNTAX, new AnySyntax("" +
                "Currently, only PGP keys are supported.\n"));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.MNT_ROUTES_SYNTAX, new AttributeSyntaxParser(new AttributeParser.MntRoutesParser(), new Multiple(new HashMap<ObjectType, String>() {{
            put(ObjectType.AUT_NUM, "<mnt-name> [ { list of (<ipv4-address>/<prefix> or <ipv6-address>/<prefix>) } | ANY ]\n");
            put(ObjectType.INET6NUM, "<mnt-name> [ { list of <ipv6-address>/<prefix> } | ANY ]\n");
            put(ObjectType.INETNUM, "<mnt-name> [ { list of <address-prefix-range> } | ANY ]\n");
            put(ObjectType.ROUTE, "<mnt-name> [ { list of <address-prefix-range> } | ANY ]\n");
            put(ObjectType.ROUTE6, "<mnt-name> [ { list of <ipv6-address>/<prefix> } | ANY ]\n");
        }})));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.MP_DEFAULT_SYNTAX, new AttributeSyntaxParser(new MpDefaultParser(), "" +
                "to <peering> [action <action>] [networks <filter>]\n"));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.MP_EXPORT_SYNTAX, new AttributeSyntaxParser(new MpExportParser(), "" +
                "[protocol <protocol-1>] [into <protocol-1>]\n" +
                "afi <afi-list>\n" +
                "to <peering-1> [action <action-1>]\n" +
                "    .\n" +
                "    .\n" +
                "    .\n" +
                "to <peering-N> [action <action-N>]\n" +
                "announce <filter>\n"));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.MP_FILTER_SYNTAX, new AttributeSyntaxParser(new MpFilterParser(), "" +
                "Logical expression which when applied to a set of multiprotocol\n" +
                "routes returns a subset of these routes. Please refer to RPSLng\n" +
                "Internet Draft for more information.\n"));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.MP_IMPORT_SYNTAX, new AttributeSyntaxParser(new MpImportParser(), "" +
                "[protocol <protocol-1>] [into <protocol-1>]\n" +
                "afi <afi-list>\n" +
                "from <peering-1> [action <action-1>]\n" +
                "    .\n" +
                "    .\n" +
                "    .\n" +
                "from <peering-N> [action <action-N>]\n" +
                "accept (<filter>|<filter> except <importexpression>|\n" +
                "        <filter> refine <importexpression>)\n"));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.MP_MEMBERS_SYNTAX, new MembersSyntax(true));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.MP_PEER_SYNTAX, new AttributeSyntaxParser(new MpPeerParser(), new Multiple(new HashMap<ObjectType, String>() {{
            put(ObjectType.INET_RTR, "" +
                    "<protocol> afi <afi> <ipv4- or ipv6- address> <options>\n" +
                    "| <protocol> <inet-rtr-name> <options>\n" +
                    "| <protocol> <rtr-set-name> <options>\n" +
                    "| <protocol> <peering-set-name> <options>\n");

            put(ObjectType.PEERING_SET, "" +
                    "afi <afi> <peering>\n");

        }})));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.MP_PEERING_SYNTAX, new AttributeSyntaxParser(new MpPeeringParser(), "" +
                "afi <afi> <peering>\n"));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.NETNAME_SYNTAX, new AttributeSyntaxRegexp(80, Pattern.compile("(?i)^[A-Z]([A-Z0-9_-]*[A-Z0-9])?$"), "" +
                "Made up of letters, digits, the character underscore \"_\",\n" +
                "and the character hyphen \"-\"; the first character of a name\n" +
                "must be a letter, and the last character of a name must be a\n" +
                "letter or a digit.\n"));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.NIC_HANDLE_SYNTAX, new AttributeSyntaxRegexp(30, Pattern.compile("(?i)^([A-Z]{2,4}([1-9][0-9]{0,5})?(-[A-Z]{2,6})?|AUTO-[1-9][0-9]*([A-Z]{2,4})?)$"), "" +
                "From 2 to 4 characters optionally followed by up to 6 digits\n" +
                "optionally followed by a source specification.  The first digit\n" +
                "must not be \"0\".  Source specification starts with \"-\" followed\n" +
                "by source name up to 9-character length.\n"));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.NSERVER_SYNTAX, new AttributeSyntaxParser(new AttributeParser.NServerParser(), "" +
                "Nameserver name as specified in RFC 1034 with or without\n" +
                "trailing dot (\".\").  The total length should not exceed\n" +
                "254 characters (octets).\n" +
                "\n" +
                "The nameserver name may be optionally followed by IPv4 address\n" +
                "in decimal dotted quad form (e.g. 192.0.2.1) or IPv6 address\n" +
                "in lowercase canonical form (Section 2.2.1, RFC 4291).\n" +
                "\n" +
                "The nameserver name may be followed by an IP address only when\n" +
                "the name is inside of the domain being delegated.\n"));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.NUMBER_SYNTAX, new AttributeSyntaxRegexp(Pattern.compile("^[0-9]+$"), "" +
                "Specifies a numeric value.\n"));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.OBJECT_NAME_SYNTAX, new AttributeSyntaxParser(new NameParser(), "" +
                "Made up of letters, digits, the character underscore \"_\",\n" +
                "and the character hyphen \"-\"; the first character of a name\n" +
                "must be a letter, and the last character of a name must be a\n" +
                "letter or a digit.  The following words are reserved by\n" +
                "RPSL, and they can not be used as names:\n" +
                "\n" +
                " any as-any rs-any peeras and or not atomic from to at\n" +
                " action accept announce except refine networks into inbound\n" +
                " outbound\n" +
                "\n" +
                "Names starting with certain prefixes are reserved for\n" +             // TODO: [ES] implement per type
                "certain object types.  Names starting with \"as-\" are\n" +
                "reserved for as set names.  Names starting with \"rs-\" are\n" +
                "reserved for route set names.  Names starting with \"rtrs-\"\n" +
                "are reserved for router set names. Names starting with\n" +
                "\"fltr-\" are reserved for filter set names. Names starting\n" +
                "with \"prng-\" are reserved for peering set names. Names\n" +
                "starting with \"irt-\" are reserved for irt names.\n"));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.SOURCE_SYNTAX, new AttributeSyntaxRegexp(80,
                Pattern.compile("(?i)^[A-Z][A-Z0-9_-]*[A-Z0-9]$"), "" +
                "Made up of letters, digits, the character underscore \"_\",\n" +
                "and the character hyphen \"-\"; the first character of a\n" +
                "registry name must be a letter, and the last character of a\n" +
                "registry name must be a letter or a digit."));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.ORGANISATION_SYNTAX, new AttributeSyntaxRegexp(30,
                Pattern.compile("(?i)^(ORG-[A-Z]{2,4}([1-9][0-9]{0,5})?-[A-Z][A-Z0-9_-]*[A-Z0-9]|AUTO-[1-9][0-9]*([A-Z]{2,4})?)$"), "" +
                "The 'ORG-' string followed by 2 to 4 characters, followed by up to 5 digits\n" +
                "followed by a source specification.  The first digit must not be \"0\".\n" +
                "Source specification starts with \"-\" followed by source name up to\n" +
                "9-character length.\n"));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.ORG_NAME_SYNTAX, new AttributeSyntaxRegexp(
                Pattern.compile("(?i)^[\\]\\[A-Z0-9._\"*()@,&:!'`+\\/-]{1,64}( [\\]\\[A-Z0-9._\"*()@,&:!'`+\\/-]{1,64}){0,29}$"), "" +
                "A list of words separated by white space.  A word is made up of letters,\n" +
                "digits, the character underscore \"_\", and the character hyphen \"-\";\n" +
                "the first character of a word must be a letter or digit; the last\n" +
                "character of a word must be a letter, digit or a dot.\n"));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.ORG_TYPE_SYNTAX, new OrgTypeSyntax());

        put(attributeSyntaxTypeMap, AttributeSyntaxType.PEER_SYNTAX, new AttributeSyntaxParser(new PeerParser(), "" +
                "<protocol> <ipv4-address> <options>\n" +
                "| <protocol> <inet-rtr-name> <options>\n" +
                "| <protocol> <rtr-set-name> <options>\n" +
                "| <protocol> <peering-set-name> <options>\n"));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.PEERING_SYNTAX, new AttributeSyntaxParser(new PeeringParser(), "" +
                "<peering>\n"));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.PERSON_ROLE_NAME_SYNTAX, new PersonRoleSyntax());

        put(attributeSyntaxTypeMap, AttributeSyntaxType.POEM_SYNTAX, new AttributeSyntaxRegexp(80,
                Pattern.compile("(?i)^POEM-[A-Z0-9][A-Z0-9_-]*$"), "" +
                "POEM-<string>\n" +
                "\n" +
                "<string> can include alphanumeric characters, and \"_\" and\n" +
                "\"-\" characters.\n"));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.POETIC_FORM_SYNTAX, new AttributeSyntaxRegexp(80,
                Pattern.compile("(?i)^FORM-[A-Z0-9][A-Z0-9_-]*$"), "" +
                "FORM-<string>\n" +
                "\n" +
                "<string> can include alphanumeric characters, and \"_\" and\n" +
                "\"-\" characters.\n"));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.PINGABLE_SYNTAX, new RoutePrefixSyntax());

        put(attributeSyntaxTypeMap, AttributeSyntaxType.PHONE_SYNTAX, new AttributeSyntaxRegexp(30,
                Pattern.compile("" +
                        "(?i)^" +
                        "[+][0-9. -]+" +                   // "normal" phone numbers
                        "(?:[(][0-9. -]+[)][0-9. -]+)?" +  // a possible '(123)' at the end
                        "(?:ext[.][0-9. -]+)?" +           // a possible 'ext. 123' at the end
                        "$"), "" +
                "Contact telephone number. Can take one of the forms:\n" +
                "\n" +
                "'+' <integer-list>\n" +
                "'+' <integer-list> \"(\" <integer-list> \")\" <integer-list>\n" +
                "'+' <integer-list> ext. <integer list>\n" +
                "'+' <integer-list> \"(\" integer list \")\" <integer-list> ext. <integer-list>\n"));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.ROUTE_SET_SYNTAX, new AttributeSyntaxParser(new AttributeParser.RouteSetParser(), "" +
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
                "route-set names.\n"));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.RTR_SET_SYNTAX, new AttributeSyntaxParser(new AttributeParser.RtrSetParser(), "" +
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
                "to be router-set names.\n"));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.PEERING_SET_SYNTAX, new AttributeSyntaxParser(new AttributeParser.PeeringSetParser(), "" +
                "A peering-set name is made up of letters, digits, the\n" +
                "character underscore \"_\", and the character hyphen \"-\"; it\n" +
                "must start with \"prng-\", and the last character of a name\n" +
                "must be a letter or a digit.\n" +
                "\n" +
                "A peering-set name can also be hierarchical.  A hierarchical\n" +
                "set name is a sequence of set names and AS numbers separated\n" +
                "by colons \":\".  At least one component of such a name must\n" +
                "be an actual set name (i.e. start with \"prng-\").  All the\n" +
                "set name components of a hierarchical peering-set name have\n" +
                "to be peering-set names.\n"));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.ROUTE_SYNTAX, new AttributeSyntaxParser(new AttributeParser.RouteResourceParser(), "" +
                "An address prefix is represented as an IPv4 address followed\n" +
                "by the character slash \"/\" followed by an integer in the\n" +
                "range from 0 to 32.  The following are valid address\n" +
                "prefixes: 128.9.128.5/32, 128.9.0.0/16, 0.0.0.0/0; and the\n" +
                "following address prefixes are invalid: 0/0, 128.9/16 since\n" +
                "0 or 128.9 are not strings containing four integers.\n"));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.ROUTE6_SYNTAX, new AttributeSyntaxParser(new AttributeParser.Route6ResourceParser(), "" +
                "<ipv6-address>/<prefix>\n"));

        put(attributeSyntaxTypeMap, AttributeSyntaxType.STATUS_SYNTAX, new StatusSyntax());

    }

    public static Map<AttributeSyntaxType, AttributeSyntax> getAttributeSyntaxMap() {
        return attributeSyntaxTypeMap;
    }

    private static void put(Map<AttributeSyntaxType, AttributeSyntax> map, AttributeSyntaxType attributeSyntaxType, AttributeSyntax syntax) {
        if (map.get(attributeSyntaxType) == null) {
            map.put(attributeSyntaxType, syntax);
        } else {
            throw new BeanInitializationException("Attribute Syntax duplicate mapping exception: " + attributeSyntaxType);
        }
    }
}
