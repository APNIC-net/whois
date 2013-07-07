package net.apnic.db.whois.common.rpsl;

import net.ripe.db.whois.common.domain.attrs.OrgType;
import net.ripe.db.whois.common.generated.AggrBndryParser;
import net.ripe.db.whois.common.generated.AggrMtdParser;
import net.ripe.db.whois.common.generated.DefaultParser;
import net.ripe.db.whois.common.generated.ExportParser;
import net.ripe.db.whois.common.generated.FilterParser;
import net.ripe.db.whois.common.generated.IfaddrParser;
import net.ripe.db.whois.common.generated.ImportParser;
import net.ripe.db.whois.common.generated.InterfaceParser;
import net.ripe.db.whois.common.generated.MpDefaultParser;
import net.ripe.db.whois.common.generated.MpExportParser;
import net.ripe.db.whois.common.generated.MpFilterParser;
import net.ripe.db.whois.common.generated.MpImportParser;
import net.ripe.db.whois.common.generated.MpPeerParser;
import net.ripe.db.whois.common.generated.MpPeeringParser;
import net.ripe.db.whois.common.generated.PeerParser;
import net.ripe.db.whois.common.generated.PeeringParser;
import net.ripe.db.whois.common.rpsl.AttributeParser;
import net.ripe.db.whois.common.rpsl.AttributeSyntax;
import net.ripe.db.whois.common.rpsl.ObjectType;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

public abstract class AttributeSyntaxImpl implements AttributeSyntax {

    // Initialize with default map
    static Map<AttributeSyntaxType, AttributeSyntax> attributeSyntaxTypeMap = new HashMap<AttributeSyntaxType, AttributeSyntax>();

    public static Map<AttributeSyntaxType, AttributeSyntax> getAttributeSyntaxMap() {
        return attributeSyntaxTypeMap;
    }

    // Override with custom syntaxes here
    static {
        attributeSyntaxTypeMap.put(AttributeSyntaxType.ANY_SYNTAX, new AnySyntax());

        // No tests for this
        attributeSyntaxTypeMap.put(AttributeSyntaxType.ADDRESS_PREFIX_RANGE_SYNTAX, new AttributeSyntaxRegexp(
                Pattern.compile("^((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))/([12]?[0-9]|3[012])$"), "" +
                "An IP address prefix represented as an IPv4 address followed\n" +
                "by the character slash \"/\" followed by an integer in the\n" +
                "range from 0 to 32.\n"));


//
//        attributeSyntaxTypeMap.put(AttributeSyntaxType.ALIAS_SYNTAX,new AttributeSyntaxRegexp(254,
//                Pattern.compile("(?i)^[A-Z0-9]([-A-Z0-9]*[A-Z0-9])?(\\.[A-Z0-9]([-A-Z0-9]*[A-Z0-9])?)*(\\.)?$"), "" +
//                "Domain name as specified in RFC 1034 (point 5.2.1.2) with or\n" +:1
//                "without trailing dot (\".\").  The total length should not exceed\n" +
//                "254 characters (octets).\n"));
//

        // Taking core regex
        attributeSyntaxTypeMap.put(AttributeSyntaxType.AS_BLOCK_SYNTAX, new AttributeSyntaxRegexp(
                Pattern.compile("(?i)^AS(0|[1-9][0-9]{0,8}|[1-3][0-9]{9}|4[01][0-9]{8}|42[0-8][0-9]{7}|429[0-3][0-9]{6}|4294[0-8][0-9]{5}|42949[0-5][0-9]{4}|429496[0-6][0-9]{3}|4294967[01][0-9]{2}|42949672[0-8][0-9]{1}|429496729[0-5]) - AS(0|[1-9][0-9]{0,8}|[1-3][0-9]{9}|4[01][0-9]{8}|42[0-8][0-9]{7}|429[0-3][0-9]{6}|4294[0-8][0-9]{5}|42949[0-5][0-9]{4}|429496[0-6][0-9]{3}|4294967[01][0-9]{2}|42949672[0-8][0-9]{1}|429496729[0-5])$"), "" +
                "<as-number> - <as-number>\n"));

        attributeSyntaxTypeMap.put(AttributeSyntaxType.AS_NUMBER_SYNTAX, new AttributeSyntaxRegexp(12,
                Pattern.compile("(?i)^AS(0|[1-9][0-9]{0,8}|[1-3][0-9]{9}|4[01][0-9]{8}|42[0-8][0-9]{7}|429[0-3][0-9]{6}|4294[0-8][0-9]{5}|42949[0-5][0-9]{4}|429496[0-6][0-9]{3}|4294967[01][0-9]{2}|42949672[0-8][0-9]{1}|429496729[0-5])$"), "" +
                "     Four-byte ASNs    AS<high order 16 bit value in decimal>.\n" +
                "                       <low order 16 bit value in decimal>\n"));

        attributeSyntaxTypeMap.put(AttributeSyntaxType.AS_SET_SYNTAX, new AttributeSyntaxRegexp(80,
                Pattern.compile("(?i)^((AS(0|[1-9][0-9]{0,8}|[1-3][0-9]{9}|4[01][0-9]{8}|42[0-8][0-9]{7}|429[0-3][0-9]{6}|4294[0-8][0-9]{5}|42949[0-5][0-9]{4}|429496[0-6][0-9]{3}|4294967[01][0-9]{2}|42949672[0-8][0-9]{1}|429496729[0-5])|as-[A-Z0-9_-]*[A-Z0-9]):)*as-[A-Z0-9_-]*[A-Z0-9](:(AS(0|[1-9][0-9]{0,8}|[1-3][0-9]{9}|4[01][0-9]{8}|42[0-8][0-9]{7}|429[0-3][0-9]{6}|4294[0-8][0-9]{5}|42949[0-5][0-9]{4}|429496[0-6][0-9]{3}|4294967[01][0-9]{2}|42949672[0-8][0-9]{1}|429496729[0-5])|as-[A-Z0-9_-]*[A-Z0-9]))*$"),
                "" +
                "An as-set name is made up of letters, digits, the\n" +
                "character underscore \"_\", and the character hyphen \"-\"; it\n" +
                "must start with \"AS-\", and the last character of a name must\n" +
                "be a letter or a digit.\n" +
                "\n" +
                "Advanced syntax:\n" +
                "\n" +
                "An as-set name can also be hierarchical.  A hierarchical as-set\n" +
                "name is a sequence of as-set names and AS numbers separated by\n" +
                "colons \":\".  At least one component of such a name must be\n" +
                "an actual set name (i.e. start with \"AS-\").\n"));

        attributeSyntaxTypeMap.put(AttributeSyntaxType.AGGR_BNDRY_SYNTAX, new AttributeSyntaxParser(new AggrBndryParser(), "" +
                "[<as-expression>]\n"));

        attributeSyntaxTypeMap.put(AttributeSyntaxType.AGGR_MTD_SYNTAX,  new AttributeSyntaxParser(new AggrMtdParser(), "" +
                "inbound | outbound [<as-expression>]\n"));

//
        attributeSyntaxTypeMap.put(AttributeSyntaxType.AUTH_SCHEME_SYNTAX, new AttributeSyntaxRegexp(90,
                Pattern.compile("(?i)^(CRYPT-PW [A-Z0-9./]{13}|MD5-PW \\$1\\$[A-Z0-9./]{1,8}\\$[A-Z0-9./]{22}|PGPKEY-[A-F0-9]{8}|X509-[1-9][0-9]*|AUTO-[1-9][0-9]*)$"),
                "" +
                "<auth-scheme> <scheme-info>       Description\n" +
                "\n" +
                "CRYPT-PW      encrypted           This is the weakest form of authentication\n" +
                "              password,           in the database as a password can only\n" +
                "              produced by         be up to eight characters in length.\n" +
                "              UNIX crypt(3)       It is by no means meant to keep out a\n" +
                "              routine             determined  malicious attacker. The crypt\n" +
                "                                  function is vulnerable to exhaustive\n" +
                "                                  search by (lots of) fast machines and\n" +
                "                                  programs to do the searching are widely\n" +
                "                                  available. For this reason it is strongly\n" +
                "                                  discouraged to use encrypted passwords\n" +
                "                                  also used for other purposes such as\n" +
                "                                  UNIX login accounts in this scheme. As\n" +
                "                                  you are publishing the encrypted\n" +
                "                                  password in the database, it is open to\n" +
                "                                  attack. The usual caveats about crypt\n" +
                "                                  passwords apply, so it is not very wise\n" +
                "                                  to use words or combinations of words\n" +
                "                                  found in any dictionary of any\n" +
                "                                  language.\n" +
                "\n" +
                "MD5-PW        encrypted           This scheme is similar to the CRYPT-PW\n" +
                "              password,           scheme, except it uses an MD5\n" +
                "              produced            hash rather than DES encryption to\n" +
                "              using the           generate the password. The main\n" +
                "              FreeBSD             benefit over CRYPT-PW is that pass\n" +
                "              crypt_md5           phrases up to 65 characters may\n" +
                "              algorithm           be used. All of the dangers of\n" +
                "                                  CRYPT-PW also apply to MD5-PW.\n" +
                "\n" +
                "PGPKEY-<id>                       Strong scheme of authentication. <id> is\n" +
                "                                  the PGP key ID to be used for\n" +
                "                                  authentication. This string is the same\n" +
                "                                  one that is used in the corresponding\n" +
                "                                  key-cert object's \"key-cert:\" attribute.\n" +
                "\n" +
                "X509-<nnn>                        Strong scheme of authentication.\n" +
                "                                  <nnn> is the index number of the\n" +
                "                                  corresponding key-cert object's\n" +
                "                                  \"key-cert:\" attribute (X509-nnn).\n"));

//        attributeSyntaxTypeMap.put(AttributeSyntaxType.CERTIF_SYNTAX, new AnySyntax("" +
//                "The value of the public key should be supplied either using\n" +
//                "multiple \"certif:\" attributes, or in one \"certif:\"\n" +
//                "attribute. In the first case, this is easily done by\n" +
//                "exporting the key from your local key ring in ASCII armored\n" +
//                "format and prepending each line of the key with the string\n" +
//                "\"certif:\". In the second case, line continuation should be\n" +
//                "used to represent an ASCII armored format of the key. All\n" +
//                "the lines of the exported key must be included; also the\n" +
//                "begin and end markers and the empty line which separates the\n" +
//                "header from the key body.\n"));

        attributeSyntaxTypeMap.put(AttributeSyntaxType.PUBLIC_KEY_SYNTAX, new AnySyntax("" +
                "The value of the public key should be supplied using one of the\n" +
                "following:\n\n" +
                "- Multiple certif attributes\n\n" +
                "    Export the key from your local key ring in ASCII armored\n" +
                "format and prepending each line of the key with the string\n" +
                "certif.\n\n" +
                "- One certif attribute\n\n" +
                "    Use line continuation to represent an ASCII armored format\n" +
                "    of the key.\n\n" +
                "All the lines of the exported key must be included;\n" +
                "also the begin and end markers and the empty line which\n" +
                "separates the header from the key body.\n"));
        
        // # (Hash) is taken as start of a comment hence # cannot be entered changed field
        attributeSyntaxTypeMap.put(AttributeSyntaxType.CHANGED_SYNTAX, new AttributeSyntaxRegexp(
                Pattern.compile("(?i)^((([A-Z0-9~#$%&'*+=?^_`{|}~/-]+\\.)*[A-Z0-9~#$%&'*+=?^_`{|}~/-]+)|(\"[^\"@\\\\]+\";))@([A-Z0-9-]+(\\.[A-Z0-9-]+)+)( [0-9]{8})?$"), "" +
                "An e-mail address as defined in RFC 2822, followed by a date\n" +
                "in the format YYYYMMDD.\n"));

        attributeSyntaxTypeMap.put(AttributeSyntaxType.COUNTRY_CODE_SYNTAX, new AttributeSyntaxRegexp(
            Pattern.compile("^[A-Za-z]{2}$"), "" +
            "Valid two-letter ISO 3166 country code. May also include\n" +
            "the following non-ISO 3166 country codes:\n" +
            "\n" +
            "AP  - networks based in more than one country in the Asia\n" +
            "      Pacific region\n" +
            "EU  - networks based in more than one country in Europe."));

        attributeSyntaxTypeMap.put(AttributeSyntaxType.COMPONENTS_SYNTAX, new ComponentsSyntax());

        attributeSyntaxTypeMap.put(AttributeSyntaxType.DEFAULT_SYNTAX,  new AttributeSyntaxParser(new DefaultParser(), "" +
                "to <peering> [action <action>] [networks <filter>]"));

        attributeSyntaxTypeMap.put(AttributeSyntaxType.DOM_NET_SYNTAX, new AttributeSyntaxRegexp(254,
                Pattern.compile("^(([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"), "" +
                "An IPv4 address is represented as a sequence of four\n" +
                "integers in the range from 0 to 255 separated by the\n" +
                "character dot (\".\").  For example, 128.9.128.5 represents a\n" +
                "valid IPv4 address.\n"));

        attributeSyntaxTypeMap.put(AttributeSyntaxType.DOMAIN_SYNTAX, new AttributeSyntaxRegexp(254,
                Pattern.compile("(?i)^[A-Z0-9]([-A-Z0-9]*[A-Z0-9])?(\\.[A-Z0-9]([-A-Z0-9]*[A-Z0-9])?)*(\\.)?$"), "" +
                "Domain name as specified in RFC 1034 without trailing dot.\n" +
                "The total length should not exceed 254 characters (octets).\n"));


        attributeSyntaxTypeMap.put(AttributeSyntaxType.DS_RDATA_SYNTAX, new AttributeSyntaxRegexp(255,
                Pattern.compile("(?i)^([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-4])( (([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])|RSAMD5|DH|DSA|ECC|RSASHA1|INDIRECT|PRIVATEDNS|PRIVATEOID))( ([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))( [(]?[ 0-9a-fA-F]{1,128}[)]?)$"), "" +
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

        // # (Hash) in Email regex is taken as start of comment. Hence cannot use # in email addresses
        attributeSyntaxTypeMap.put(AttributeSyntaxType.EMAIL_SYNTAX, new AttributeSyntaxRegexp(80,
                Pattern.compile("(?i)^((([A-Z0-9~#$%&'*+=?^_`{|}~/-]+\\.)*[A-Z0-9~#$%&'*+=?^_`{|}~/-]+)|(\"[^\"@\\\\]+\"))@([A-Z0-9-]+(\\.[A-Z0-9-]+)+)$"),
                "An e-mail address as defined in RFC 2822.\n"));

        // FOR V6_FILTER_SYNTAX
        attributeSyntaxTypeMap.put(AttributeSyntaxType.EXPORT_COMPS_SYNTAX, new ExportCompsSyntax());

        attributeSyntaxTypeMap.put(AttributeSyntaxType.EXPORT_SYNTAX, new AttributeSyntaxParser(new ExportParser(), "" +
                "[protocol <protocol-1>] [into <protocol-1>]\n" +
                "to <peering-1> [action <action-1>]\n" +
                "    .\n" +
                "    .\n" +
                "    .\n" +
                "to <peering-N> [action <action-N>]\n" +
                "announce <filter>\n"));

        attributeSyntaxTypeMap.put(AttributeSyntaxType.FILTER_SYNTAX, new AttributeSyntaxParser(new FilterParser(), "" +
                "Logical expression which when applied to a set of routes\n" +
                "returns a subset of these routes. Please refer to RFC 2622\n" +
                "for more information.\n"));



        attributeSyntaxTypeMap.put(AttributeSyntaxType.FINGERPR_SYNTAX, new AttributeSyntaxRegexp(
                Pattern.compile("(?i)^(([A-F0-9]{4} ){9}[A-F0-9]{4})|(([A-F0-9]{2} ){15}[A-F0-9]{2})|(([A-F0-9]{2}:){15}[A-F0-9]{2})$"), "" +
                "Attribute generated by server.\n"));

        attributeSyntaxTypeMap.put(AttributeSyntaxType.FILTER_SET_SYNTAX,
                new AttributeSyntaxRegexp(Pattern.compile("(?i)^((AS(0|[1-9][0-9]{0,8}|[1-3][0-9]{9}|4[01][0-9]{8}|42[0-8][0-9]{7}|429[0-3][0-9]{6}|4294[0-8][0-9]{5}|42949[0-5][0-9]{4}|429496[0-6][0-9]{3}|4294967[01][0-9]{2}|42949672[0-8][0-9]{1}|429496729[0-5])|fltr-[A-Z0-9_-]*[A-Z0-9]):)*fltr-[A-Z0-9_-]*[A-Z0-9](:(AS(0|[1-9][0-9]{0,8}|[1-3][0-9]{9}|4[01][0-9]{8}|42[0-8][0-9]{7}|429[0-3][0-9]{6}|4294[0-8][0-9]{5}|42949[0-5][0-9]{4}|429496[0-6][0-9]{3}|4294967[01][0-9]{2}|42949672[0-8][0-9]{1}|429496729[0-5])|fltr-[A-Z0-9_-]*[A-Z0-9]))*$"),
                "" +
                "A filter-set name is made up of letters, digits, the\n" +
                "character underscore \"_\", and the character hyphen \"-\"; it\n" +
                "must start with \"FLTR-\", and the last character of a name\n" +
                "must be a letter or a digit.\n" +
                "\n" +
                "A filter-set name can also be hierarchical.  A hierarchical\n" +
                "set name is a sequence of set names and AS numbers separated\n" +
                "by colons \":\".  At least one component of such a name\n" +
                "must start with \"FLTR-\".  All the set name components of a\n" +
                "hierarchical filter-name have to be filter-set names.\n"));

        attributeSyntaxTypeMap.put(AttributeSyntaxType.FREE_FORM_SYNTAX,  new AttributeSyntaxRegexp(
                Pattern.compile("(?s)^.*$"), "" +
                "A sequence of ASCII characters.\n"));

//        attributeSyntaxTypeMap.put(AttributeSyntaxType.GENERATED_SYNTAX, new AnySyntax("" +
//                "Attribute generated by server."));
//
//        attributeSyntaxTypeMap.put(AttributeSyntaxType.GEOLOC_SYNTAX, new GeolocSyntax());
//
//        attributeSyntaxTypeMap.put(AttributeSyntaxType.HOLES_SYNTAX, new RoutePrefixSyntax());

        attributeSyntaxTypeMap.put(AttributeSyntaxType.IMPORT_SYNTAX, new AttributeSyntaxParser(new ImportParser(), "" +
                "[protocol <protocol-1>] [into <protocol-1>]\n" +
                "from <peering-1> [action <action-1>]\n" +
                "    .\n" +
                "    .\n" +
                "    .\n" +
                "from <peering-N> [action <action-N>]\n" +
                "accept <filter>\n"));

        attributeSyntaxTypeMap.put(AttributeSyntaxType.INET_RTR_SYNTAX, new AttributeSyntaxRegexp(254,
                Pattern.compile("(?i)^[A-Z0-9]([-_A-Z0-9]*[A-Z0-9])?(\\.[A-Z0-9]([-_A-Z0-9]*[A-Z0-9])?)*(\\.)?$"), "" +
                "Domain name as specified in RFC 1034 (point 5.2.1.2) with or\n" +
                "without trailing dot (\".\").  The total length should not exceed\n" +
                "254 characters (octets).\n"));

        attributeSyntaxTypeMap.put(AttributeSyntaxType.IFADDR_SYNTAX, new AttributeSyntaxParser(new IfaddrParser(), "" +
                "<ipv4-address> masklen <integer> [action <action>]"));

        attributeSyntaxTypeMap.put(AttributeSyntaxType.INJECT_SYNTAX, new InjectSyntax());

        attributeSyntaxTypeMap.put(AttributeSyntaxType.INTERFACE_SYNTAX, new AttributeSyntaxParser(new InterfaceParser(), "" +
                "afi <afi> <ipv4-address> masklen <integer> [action <action>]\n" +
                "afi <afi> <ipv6-address> masklen <integer> [action <action>]\n" +
                "          [tunnel <remote-endpoint-address>,<encapsulation>]\n"));


        // 192.168.1.0 - 192.168.1.255"
        attributeSyntaxTypeMap.put(AttributeSyntaxType.IPV4_SYNTAX, new AttributeSyntaxRegexp(
              Pattern.compile("^((((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])) - ((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])))|(((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))/([89]|[12][0-9]|3[012])))$"),
              "" +
              "<ipv4-address> - <ipv4-address>"));

        attributeSyntaxTypeMap.put(AttributeSyntaxType.IPV6_SYNTAX, new AttributeSyntaxParser(new AttributeParser.Ipv6ResourceParser(), "" +
                "<ipv6-address>/<prefix>"));

        attributeSyntaxTypeMap.put(AttributeSyntaxType.IRT_SYNTAX, new AttributeSyntaxRegexp(Pattern.compile("^irt-[A-Z0-9_-]*[A-Z0-9]$"), "" +
                "An irt name is made up of letters, digits, the character\n" +
                "underscore \"_\", and the character hyphen \"-\"; it must start\n" +
                "with \"IRT-\", and the last character of a name must be a\n" +
                "letter or a digit.\n"));

        attributeSyntaxTypeMap.put(AttributeSyntaxType.KEY_CERT_SYNTAX, new AttributeSyntaxRegexp(
                Pattern.compile("(?i)^(PGPKEY-[A-F0-9]{8})|(X509-[1-9][0-9]*)|(AUTO-[1-9][0-9]*)$"), "" +
                "PGPKEY-<id>\n" +
                "\n" +
                "<id> is  the PGP key ID of the public key in 8-digit\n" +
                "hexadecimal format without \"0x\" prefix."));


//        attributeSyntaxTypeMap.put(AttributeSyntaxType.LANGUAGE_CODE_SYNTAX,  new AttributeSyntaxRegexp(Pattern.compile("(?i)^[a-z]{2}$"), "" +
//                "Valid two-letter ISO 639-1 language code.\n"));
//

        attributeSyntaxTypeMap.put(AttributeSyntaxType.LIMERICK_SYNTAX, new AttributeSyntaxRegexp(80,
                Pattern.compile("(?i)^lim-[A-Z0-9_-]*$"), ""));

        attributeSyntaxTypeMap.put(AttributeSyntaxType.MBRS_BY_REF_SYNTAX,  new AttributeSyntaxRegexp(80,
                Pattern.compile("(?i)^(as-any|rs-any|peeras|and|or|not|atomic|from|to|at|action|accept|announce|except|refine|networks|into|inbound|outbound|rs-.*|rtrs-.*|fltr-.*|prng-.*)$"),
                "<mntner-name> | ANY\n"));


        attributeSyntaxTypeMap.put(AttributeSyntaxType.MEMBER_OF_SYNTAX, new MemberOfSyntax());

        // This is for members-is field.
        attributeSyntaxTypeMap.put(AttributeSyntaxType.MEMBERS_SYNTAX, new MembersSyntax(false));


//        attributeSyntaxTypeMap.put(AttributeSyntaxType.MEMBERS_AS_SYNTAX, new AttributeSyntaxRegexp(
//                Pattern.compile("(?i)^((((AS(0|[1-9][0-9]{0,8}|[1-3][0-9]{9}|4[01][0-9]{8}|42[0-8][0-9]{7}|429[0-3][0-9]{6}|4294[0-8][0-9]{5}|42949[0-5][0-9]{4}|429496[0-6][0-9]{3}|4294967[01][0-9]{2}|42949672[0-8][0-9]{1}|429496729[0-5])|as-[A-Z0-9_-]*[A-Z0-9]):)*as-[A-Z0-9_-]*[A-Z0-9](:(AS(0|[1-9][0-9]{0,8}|[1-3][0-9]{9}|4[01][0-9]{8}|42[0-8][0-9]{7}|429[0-3][0-9]{6}|4294[0-8][0-9]{5}|42949[0-5][0-9]{4}|429496[0-6][0-9]{3}|4294967[01][0-9]{2}|42949672[0-8][0-9]{1}|429496729[0-5])|as-[A-Z0-9_-]*[A-Z0-9]))*)|AS(0|[1-9][0-9]{0,8}|[1-3][0-9]{9}|4[01][0-9]{8}|42[0-8][0-9]{7}|429[0-3][0-9]{6}|4294[0-8][0-9]{5}|42949[0-5][0-9]{4}|429496[0-6][0-9]{3}|4294967[01][0-9]{2}|42949672[0-8][0-9]{1}|429496729[0-5]))$"),
//                "" +
//                "<as-number> or\n" +
//                "<as-set-name>\n"));

        attributeSyntaxTypeMap.put(AttributeSyntaxType.METHOD_SYNTAX, new AttributeSyntaxRegexp(
                Pattern.compile("^(PGP)|(X509)$"), "" +
                "Currently, only PGP keys are supported.\n"));


        attributeSyntaxTypeMap.put(AttributeSyntaxType.MNT_ROUTES_SYNTAX, new AttributeSyntaxParser(new AttributeParser.MntRoutesParser(), new Multiple(new HashMap<ObjectType, String>() {{
            put(ObjectType.AUT_NUM, "<mnt-name> [ { list of (<ipv4-address>/<prefix> or <ipv6-address>/<prefix>) } | ANY ]\n");
            put(ObjectType.INET6NUM, "<mnt-name> [ { list of <ipv6-address>/<prefix> } | ANY ]\n");
            put(ObjectType.INETNUM, "<mnt-name> [ { list of <address-prefix-range> } | ANY ]\n");
            put(ObjectType.ROUTE, "<mnt-name> [ { list of <address-prefix-range> } | ANY ]\n");
            put(ObjectType.ROUTE6, "<mnt-name> [ { list of <ipv6-address>/<prefix> } | ANY ]\n");
        }})));

        attributeSyntaxTypeMap.put(AttributeSyntaxType.MP_DEFAULT_SYNTAX, new AttributeSyntaxParser(new MpDefaultParser(), "" +
                "to <peering> [action <action>] [networks <filter>]\n"));

        attributeSyntaxTypeMap.put(AttributeSyntaxType.MP_EXPORT_SYNTAX, new AttributeSyntaxParser(new MpExportParser(), "" +
                "[protocol <protocol-1>] [into <protocol-1>]\n" +
                "afi <afi-list>\n" +
                "to <peering-1> [action <action-1>]\n" +
                "    .\n" +
                "    .\n" +
                "    .\n" +
                "to <peering-N> [action <action-N>]\n" +
                "announce <filter>\n"));

        attributeSyntaxTypeMap.put(AttributeSyntaxType.MP_FILTER_SYNTAX, new AttributeSyntaxParser(new MpFilterParser(), "" +
                "Logical expression which when applied to a set of multiprotocol\n" +
                "routes returns a subset of these routes. Please refer to RPSLng\n" +
                "Internet Draft for more information.\n"));

        attributeSyntaxTypeMap.put(AttributeSyntaxType.MP_IMPORT_SYNTAX, new AttributeSyntaxParser(new MpImportParser(), "" +
                "[protocol <protocol-1>] [into <protocol-1>]\n" +
                "afi <afi-list>\n" +
                "from <peering-1> [action <action-1>]\n" +
                "    .\n" +
                "    .\n" +
                "    .\n" +
                "from <peering-N> [action <action-N>]\n" +
                "accept (<filter>|<filter> except <importexpression>|\n" +
                "        <filter> refine <importexpression>)\n"));

        attributeSyntaxTypeMap.put(AttributeSyntaxType.MP_MEMBERS_SYNTAX, new MembersSyntax(true));



        attributeSyntaxTypeMap.put(AttributeSyntaxType.MP_PEER_SYNTAX, new AttributeSyntaxParser(new MpPeerParser(), new Multiple(new HashMap<ObjectType, String>() {{
            put(ObjectType.INET_RTR, "" +
                    "<protocol> afi <afi> <ipv4- or ipv6- address> <options>\n" +
                    "| <protocol> <inet-rtr-name> <options>\n" +
                    "| <protocol> <rtr-set-name> <options>\n" +
                    "| <protocol> <peering-set-name> <options>\n");

            put(ObjectType.PEERING_SET, "" +
                    "afi <afi> <peering>\n");

        }})));

        attributeSyntaxTypeMap.put(AttributeSyntaxType.MP_PEERING_SYNTAX, new AttributeSyntaxParser(new MpPeeringParser(), "" +
                "afi <afi> <peering>\n"));

        attributeSyntaxTypeMap.put(AttributeSyntaxType.NETNAME_SYNTAX, new AttributeSyntaxRegexp(80,
                Pattern.compile("(?i)^[A-Z]([A-Z0-9_-]*[A-Z0-9])?$"), "" +
                "Made up of letters, digits, the character underscore \"_\",\n" +
                "and the character hyphen \"-\"; the first character of a name\n" +
                "must be a letter, and the last character of a name must be a\n" +
                "letter or a digit.\n"));

        attributeSyntaxTypeMap.put(AttributeSyntaxType.NIC_HANDLE_SYNTAX, new AttributeSyntaxRegexp(30,
                Pattern.compile("(?i)^(([A-Z]{2,4}([1-9][0-9]{0,5})?(-[A-Z]([A-Z0-9_-]{0,7}[A-Z0-9]))?)|(AUTO-[0-9]+([A-Z]{2,4})?))$"),
                "" +
                "From 2 to 4 characters optionally followed by up to 5 digits with \n" +
                "the suffix \"-AP\"\n"));

        attributeSyntaxTypeMap.put(AttributeSyntaxType.NSERVER_SYNTAX, new AttributeSyntaxParser(new AttributeParser.NServerParser(), "" +
                "Nameserver name as :specified in RFC 1034 with or without\n" +
                "trailing dot (\".:1\").  The total length should not exceed\n" +
                "254 characters (octets).\n" +
                "\n" +
                "The nameserver name may be optionally followed by IPv4 address\n" +
                "in decimal dotted quad form (e.g. 192.0.2.1) or IPv6 address\n" +
                "in lowercase canonical form (Section 2.2.1, RFC 4291).\n" +
                "\n" +
                "The nameserver name may be followed by an IP address only when\n" +
                "the name is inside of the domain being delegated.\n"));

//        attributeSyntaxTypeMap.put(AttributeSyntaxType.NUMBER_SYNTAX, new AttributeSyntaxRegexp(Pattern.compile("^[0-9]+$"), "" +
//                "Specifies a numeric value.\n"));

        attributeSyntaxTypeMap.put(AttributeSyntaxType.OBJECT_NAME_SYNTAX, new AttributeSyntaxRegexp(80,
                Pattern.compile("(?i)^[A-Z]([A-Z0-9_-]*[A-Z0-9])?$"),
                "" +
                "Made up of letters, digits, the character underscore \"_\",\n" +
                "and the character hyphen \"-\"; the first character of a name\n" +
                "must be a letter, and the last character of a name must be a\n" +
                "letter or a digit.  The following words are reserved by\n" +
                "RPSL, and they can not be used as names:\n" +
                "\n" +
                "any or to refine\n" +
                "as-any not action networks\n" +
                "rs-any atomic accept into\n" +
                "peeras from announce inbound\n" +
                "and at except outbound\n" +
                "\n" +
                "Names starting with certain prefixes are reserved for\n" +
                "certain object types. Reserved prefixes are:\n" +
                "\n" +
                "AS-     reserved for as-set names\n" +
                "RS-     reserved for route-set names\n" +
                "RTRS-   reserved for rtr-set names\n" +
                "FLTR-   reserved for filter-set names\n" +
                "PRNG-   reserved for peering-set names\n" +
                "IRT-    reserved for irt names (irt not yet implemented by APNIC)\n"));

//        attributeSyntaxTypeMap.put(AttributeSyntaxType.SOURCE_SYNTAX, new AttributeSyntaxRegexp(80,
//                Pattern.compile("(?i)^[A-Z][A-Z0-9_-]*[A-Z0-9]$"), "" +
//                "Made up of letters, digits, the character underscore \"_\",\n" +
//                "and the character hyphen \"-\"; the first character of a\n" +
//                "registry name must be a letter, and the last character of a\n" +
//                "registry name must be a letter or a digit."));
//
        attributeSyntaxTypeMap.put(AttributeSyntaxType.ORGANISATION_SYNTAX, new AttributeSyntaxRegexp(30,
                Pattern.compile("(?i)^(ORG-([A-Z]{2,4}([1-9][0-9]{0,5})?(-[A-Z]([A-Z0-9_-]{0,7}[A-Z0-9])))|(AUTO-[0-9]+([A-Z]{2,4})?))$"),
                ""));

        attributeSyntaxTypeMap.put(AttributeSyntaxType.ORG_NAME_SYNTAX, new AttributeSyntaxRegexp(
                Pattern.compile("(?i)^[A-Z0-9._\"*()@,&:!'`+\\/-\\[\\]]{1,64}( [A-Z0-9._\"*()@,&:!'`+\\/-\\[\\]]{1,64}){0,11}$"),
                ""));

        attributeSyntaxTypeMap.put(AttributeSyntaxType.ORG_TYPE_SYNTAX, new AttributeSyntaxRegexp(
                Pattern.compile("(?i)^(IANA|RIR|NIR|LIR|NON-REGISTRY)$"),
                ""));

//        attributeSyntaxTypeMap.put(AttributeSyntaxType.PEER_SYNTAX, new AttributeSyntaxParser(new PeerParser(), "" +
//                "<protocol> <ipv4-address> <options>\n" +
//                "| <protocol> <inet-rtr-name> <options>\n" +
//                "| <protocol> <rtr-set-name> <options>\n" +
//                "| <protocol> <peering-set-name> <options>\n"));

        attributeSyntaxTypeMap.put(AttributeSyntaxType.PEERING_SYNTAX, new AttributeSyntaxParser(new PeeringParser(), "" +
                "<peering>\n"));

        attributeSyntaxTypeMap.put(AttributeSyntaxType.PEERING_SET_SYNTAX, new AttributeSyntaxRegexp(80,
                Pattern.compile("(?i)^((AS(0|[1-9][0-9]{0,8}|[1-3][0-9]{9}|4[01][0-9]{8}|42[0-8][0-9]{7}|429[0-3][0-9]{6}|4294[0-8][0-9]{5}|42949[0-5][0-9]{4}|429496[0-6][0-9]{3}|4294967[01][0-9]{2}|42949672[0-8][0-9]{1}|429496729[0-5])|prng-[A-Z0-9_-]*[A-Z0-9]):)*prng-[A-Z0-9_-]*[A-Z0-9](:(AS(0|[1-9][0-9]{0,8}|[1-3][0-9]{9}|4[01][0-9]{8}|42[0-8][0-9]{7}|429[0-3][0-9]{6}|4294[0-8][0-9]{5}|42949[0-5][0-9]{4}|429496[0-6][0-9]{3}|4294967[01][0-9]{2}|42949672[0-8][0-9]{1}|429496729[0-5])|prng-[A-Z0-9_-]*[A-Z0-9]))*$"),
                "" +
                        "A peering-set name is made up of letters, digits, the\n" +
                        "character underscore \"_\", and the character hyphen \"-\"; it\n" +
                        "must start with \"PRNG-\", and the last character of a name\n" +
                        "must be a letter or a digit.\n" +
                        "\n" +
                        "Advanced syntax:\n" +
                        "\n" +
                        "A peering-set name can also be hierarchical.  A \n" +
                        "hierarchical set name is a sequence of set names and AS \n" +
                        "numbers separated by colons \":\".  At least one component of \n" +
                        "such a name must start with \"PRNG-\".  All the set name\n" +
                        "components of a hierarchical peering-set name have to be \n" +
                        "peering-set names.\n"));

        attributeSyntaxTypeMap.put(AttributeSyntaxType.PERSON_NAME_SYNTAX, new AttributeSyntaxRegexp(80,
                Pattern.compile("(?i)^[A-Z]([A-Z0-9.`'_-]*[A-Z0-9`'_-])?([\\s]+[A-Z0-9.`'_-]+)*[\\s]+[A-Z]([A-Z0-9.`'_-]*[A-Z0-9`'_-])?$"), "" +
                "A list of at least 2 words composed of alphabetic characters\n" +
                "separated by white space. The first and the last word cannot end\n" +
                "with dot (\".\"). The following words are not allowed no matter\n" +
                "whether they end with dot (\".\") or not:\n" +
                "\n" +
                "Dr     Prof    Mv\n" +
                "Ms     Mr      Mrs\n" +
                "\n" +
                "A word is made up of letters, digits, and the underscore\"_\",\n" +
                "and hyphen \"-\" characters. The first character of a word must\n" +
                "be a letter, and the last character of a name must be a letter\n" +
                "or a digit.\n"));


//        attributeSyntaxTypeMap.put(AttributeSyntaxType.PERSON_ROLE_NAME_SYNTAX, new PersonRoleSyntax());

        attributeSyntaxTypeMap.put(AttributeSyntaxType.POEM_SYNTAX, new AttributeSyntaxRegexp(80,
                Pattern.compile("(?i)^POEM-[A-Z0-9][A-Z0-9_-]*$"), "" +
                "POEM-<string>\n" +
                "\n" +
                "<string> can include alphanumeric characters, and \"_\" and\n" +
                "\"-\" characters.\n"));

        attributeSyntaxTypeMap.put(AttributeSyntaxType.PHONE_SYNTAX, new AttributeSyntaxRegexp(30,
                Pattern.compile("(?i)^\\+\\s*[0-9][0-9.\\s-]*(\\([0-9.\\s-]*[0-9][0-9.\\s-]*\\))?([0-9.\\s-]*[0-9][0-9.\\s-]*)?([\\s]+ext.[0-9.\\s-]*[0-9][0-9.\\s-]*)?$"),
                "" +
                        "Contact telephone number. Can take one of the forms:\n" +
                        "\n" +
                        "+  <country code> <phone number> OR\n" +
                        "+  <country code> <area code> <phone number> OR\n" +
                        "+  <country code> <area code> <phone number> ext. <number>\n"));

//        attributeSyntaxTypeMap.put(AttributeSyntaxType.PINGABLE_SYNTAX, new RoutePrefixSyntax());

        attributeSyntaxTypeMap.put(AttributeSyntaxType.POETIC_FORM_SYNTAX, new AttributeSyntaxRegexp(80,
                Pattern.compile("(?i)^FORM-[A-Z0-9][A-Z0-9_-]*$"), "" +
                "FORM-<string>\n" +
                "\n" +
                "<string> can include alphanumeric characters, and \"_\" and\n" +
                "\"-\" characters.\n"));

//        attributeSyntaxTypeMap.put(AttributeSyntaxType.REFER_SYNTAX, new AttributeSyntaxParser(new AttributeParser.ReferParser(), "" +
//                "Syntax:\n" +
//                "\n" +
//                "<type> <hostname> [<port>]\n" +
//                "type       The type of referral to be used. Supported types\n" +
//                "           are:\n" +
//                "             - SIMPLE\n" +
//                "             - INTERNIC\n" +
//                "             - RIPE\n" +
//                "             - CLIENTADDRESS\n" +
//                "\n" +
//                "hostname   The DNS name or IPv4 address of the referred host.\n" +
//                "\n" +
//                "port       The TCP port number at which queries are accepted\n" +
//                "                by the referred host.  If &lt;port&gt; is omitted, the\n" +
//                "                default number, 43, is used."));


        attributeSyntaxTypeMap.put(AttributeSyntaxType.REFERRAL_BY_SYNTAX,  new AttributeSyntaxRegexp(
                Pattern.compile("(?i)^APNIC-DBM-MNT$"), "" +
                "Only APNIC-DBM-MNT is allowed.\n"));

        attributeSyntaxTypeMap.put(AttributeSyntaxType.REGISTRY_NAME_SYNTAX,  new AttributeSyntaxRegexp(
                Pattern.compile("(?i)^[A-Za-z]([A-Za-z0-9_-]*[A-Za-z0-9])?$"), "" +
                "Use \"APNIC\" only for the APNIC Whois Database.\n"));

        attributeSyntaxTypeMap.put(AttributeSyntaxType.ROUTE_SET_SYNTAX, new AttributeSyntaxRegexp(80,
                Pattern.compile("(?i)^((AS(0|[1-9][0-9]{0,8}|[1-3][0-9]{9}|4[01][0-9]{8}|42[0-8][0-9]{7}|429[0-3][0-9]{6}|4294[0-8][0-9]{5}|42949[0-5][0-9]{4}|429496[0-6][0-9]{3}|4294967[01][0-9]{2}|42949672[0-8][0-9]{1}|429496729[0-5])|rs-[A-Z0-9_-]*[A-Z0-9]):)*rs-[A-Z0-9_-]*[A-Z0-9](:(AS(0|[1-9][0-9]{0,8}|[1-3][0-9]{9}|4[01][0-9]{8}|42[0-8][0-9]{7}|429[0-3][0-9]{6}|4294[0-8][0-9]{5}|42949[0-5][0-9]{4}|429496[0-6][0-9]{3}|4294967[01][0-9]{2}|42949672[0-8][0-9]{1}|429496729[0-5])|rs-[A-Z0-9_-]*[A-Z0-9]))*$"),
                "" +
                "An route-set name is made up of letters, digits, the\n" +
                "character underscore \"_\", and the character hyphen \"-\"; it\n" +
                "must start with \"RS-\", and the last character of a name must\n" +
                "be a letter or a digit.\n" +
                "\n" +
                "Advanced syntax:\n" +
                "\n" +
                "A route-set name can also be hierarchical.  A hierarchical\n" +
                "set name is a sequence of route-set names and AS numbers separated\n" +
                "by colons \":\".  At least one component of such a name must\n" +
                "be an actual route-set name (i.e. start with \"RS-\").\n"));

        attributeSyntaxTypeMap.put(AttributeSyntaxType.RTR_SET_SYNTAX, new AttributeSyntaxRegexp(80,
                Pattern.compile("(?i)^((AS(0|[1-9][0-9]{0,8}|[1-3][0-9]{9}|4[01][0-9]{8}|42[0-8][0-9]{7}|429[0-3][0-9]{6}|4294[0-8][0-9]{5}|42949[0-5][0-9]{4}|429496[0-6][0-9]{3}|4294967[01][0-9]{2}|42949672[0-8][0-9]{1}|429496729[0-5])|rtrs-[A-Z0-9_-]*[A-Z0-9]):)*rtrs-[A-Z0-9_-]*[A-Z0-9](:(AS(0|[1-9][0-9]{0,8}|[1-3][0-9]{9}|4[01][0-9]{8}|42[0-8][0-9]{7}|429[0-3][0-9]{6}|4294[0-8][0-9]{5}|42949[0-5][0-9]{4}|429496[0-6][0-9]{3}|4294967[01][0-9]{2}|42949672[0-8][0-9]{1}|429496729[0-5])|rtrs-[A-Z0-9_-]*[A-Z0-9]))*$"),
                "" +
                        "A router-set name is made up of letters, digits, the\n" +
                        "character underscore \"_\", and the character hyphen \"-\"; it\n" +
                        "must start with \"RTRS-\", and the last character of a name\n" +
                        "must be a letter or a digit.\n" +
                        "\n" +
                        "A router-set name can also be hierarchical.  A hierarchical\n" +
                        "set name is a sequence of set names and AS numbers separated\n" +
                        "by colons \":\".  At least one component of such a name must\n" +
                        "be an actual set name (i.e. start with \"RTRS-\").  All the\n" +
                        "set name components of a hierarchical router-set name have\n" +
                        "to be router-set names.\n"));

//        attributeSyntaxTypeMap.put(AttributeSyntaxType.ROUTE_SYNTAX, new AttributeSyntaxParser(new AttributeParser.RouteResourceParser(), "" +
//                "An address prefix is represented as an IPv4 address followed\n" +
//                "by the character slash \"/\" followed by an integer in the\n" +
//                "range from 0 to 32.  The following are valid address\n" +
//                "prefixes: 128.9.128.5/32, 128.9.0.0/16, 0.0.0.0/0; and the\n" +
//                "following address prefixes are invalid: 0/0, 128.9/16 since\n" +
//                "0 or 128.9 are not strings containing four integers.\n"));
//
//        attributeSyntaxTypeMap.put(AttributeSyntaxType.ROUTE6_SYNTAX, new AttributeSyntaxParser(new AttributeParser.Route6ResourceParser(), "" +
//                "<ipv6-address>/<prefix>\n"));
//
          // The following statement has been changed and not working.  Found that need to change RIPE inetnumStatus module to suit APNIC
          attributeSyntaxTypeMap.put(AttributeSyntaxType.STATUS_SYNTAX, new AttributeSyntaxRegexp(
                Pattern.compile("(?i)^(ALLOCATED|ASSIGNED) (PORTABLE|NON-PORTABLE)$"), "" +
                "Status can have one of these values:\n" +
                "\n" +
                "- ALLOCATED PORTABLE\n" +
                "- ALLOCATED NON-PORTABLE\n" +
                "- ASSIGNED PORTABLE\n" +
                "- ASSIGNED NON-PORTABLE\n"));

        // The following statement has been changed and not working.  Found that need to change RIPE inetnumStatus module to suit APNIC
        attributeSyntaxTypeMap.put(AttributeSyntaxType.SUBDOMAIN_NAME_SYNTAX, new AttributeSyntaxRegexp(
                Pattern.compile("[A-Za-z0-9]([-A-Za-z0-9]*[A-Za-z0-9])?(\\.[A-Za-z0-9]([-A-Za-z0-9]*[A-Za-z0-9])?)*(\\.)?$"), "" +

                "     Domain name as specified in RFC 1034 without trailing dot\n" +
                "     (\".\").  The total length should not exceed 254 characters\n" +
                "     (octets).\n"));
}

//    public static class OrgTypeSyntax implements AttributeSyntax {
//        @Override
//        public boolean matches(final ObjectType objectType, final String value) {
//            return OrgType.getFor(value) != null;
//        }
//
//        @Override
//        public String getDescription(final ObjectType objectType) { // TODO [AK] Generate possible values from OrgType
//            return "" +
//                    "org-type can have one of these values:\n" +
//                    "\n" +
//                    "o IANA\n" +
//                    "o RIR\n" +
//                    "o NIR (There are no NIRs in the APNIC service region.)\n" +
//                    "o LIR\n" +
//                    "o WHITEPAGES\n" +
//                    "o DIRECT_ASSIGNMENT\n" +
//                    "o OTHER\n" +
//                    "\n" +
//                    "    'IANA' for Internet Assigned Numbers Authority\n" +
//                    "    'RIR' for Regional Internet Registries\n" +
//                    "    'NIR' for National Internet Registries\n" +
//                    "    'LIR' for Local Internet Registries\n" +
//                    "    'WHITEPAGES' for special links to industry people\n" +
//                    "    'DIRECT_ASSIGNMENT' for direct contract with APNIC\n" +
//                    "    'OTHER' for all other organisations.\n";
//        }
//    }
}
