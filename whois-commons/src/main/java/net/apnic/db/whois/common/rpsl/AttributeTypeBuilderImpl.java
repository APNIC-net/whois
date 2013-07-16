package net.apnic.db.whois.common.rpsl;

import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import net.ripe.db.whois.common.rpsl.AttributeSyntax;
import net.ripe.db.whois.common.rpsl.AttributeTypeBuilder;
import net.ripe.db.whois.common.rpsl.AttributeValueType;
import net.ripe.db.whois.common.rpsl.Documented;
import net.ripe.db.whois.common.rpsl.ObjectType;
import org.springframework.beans.factory.BeanInitializationException;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static net.ripe.db.whois.common.rpsl.AttributeValueType.LIST_VALUE;

public class  AttributeTypeBuilderImpl implements AttributeTypeBuilder {
    static Map<Enum, AttributeTypeBuilder> localMap = new HashMap<Enum, AttributeTypeBuilder>();

    static {
        // Please check .doc description against attribute.xml
        put(new AttributeTypeBuilderImpl("abuse-mailbox", "am", Enum.ABUSE_MAILBOX)
                .doc("Specifies the e-mail address to which abuse complaints should be sent.")
                .syntax(AttributeSyntax.EMAIL_SYNTAX));

        put(new AttributeTypeBuilderImpl("abuse-c", "au", Enum.ABUSE_C)
                .doc("References an abuse contact. " +
                        "This can only be a ROLE object containing an \"abuse-mailbox:\" attribute. " +
                        "Making this reference will remove any query limits for the ROLE object. " +
                        "These ROLE objects are considered to include only commercial data.")
                .syntax(AttributeSyntax.NIC_HANDLE_SYNTAX)
                .references(ObjectType.ROLE));

        put(new AttributeTypeBuilderImpl("address", "ad", Enum.ADDRESS)
                .doc("Full postal address of a contact")
                .syntax(AttributeSyntax.FREE_FORM_SYNTAX));

        put(new AttributeTypeBuilderImpl("admin-c", "ac", Enum.ADMIN_C)
                .doc("The NIC-handle of an on-site administrative contact.")
                .syntax(AttributeSyntax.NIC_HANDLE_SYNTAX)
                .references(ObjectType.PERSON, ObjectType.ROLE));

        put(new AttributeTypeBuilderImpl("aggr-bndry", "ab", Enum.AGGR_BNDRY)
                .doc("Defines a set of Autonomous Systems which form the aggregation boundary.")
                .syntax(AttributeSyntax.AGGR_BNDRY_SYNTAX));

        put(new AttributeTypeBuilderImpl("aggr-mtd", "ag", Enum.AGGR_MTD)
                .doc("Specifies how the aggregate is generated.")
                .syntax(AttributeSyntax.AGGR_MTD_SYNTAX));

        put(new AttributeTypeBuilderImpl("alias", "az", Enum.ALIAS)
                .doc("The canonical DNS name for the router.")
                .syntax(AttributeSyntax.ALIAS_SYNTAX));

        put(new AttributeTypeBuilderImpl("address-prefix", "ap", Enum.APNIC_ADDRESS_PREFIX_RANGE)
                .doc("Specifies a range of IPv4 that inetnum object presents. " +
                        "The ending address should be greater than the starting one.")
                .syntax(AttributeSyntax.ADDRESS_PREFIX_RANGE_SYNTAX));

        put(new AttributeTypeBuilderImpl("dom-net", "di", Enum.APNIC_DOM_NET)
                .doc("This attribute is not applicable to reverse domains. Do not use " +
                        "this attribute.")
                .syntax(AttributeSyntax.APNIC_DOM_NET_SYNTAX));

        // Not in current attribute.xml
        put(new AttributeTypeBuilderImpl("registry-name", "rg", Enum.APNIC_REGISTRY_NAME)
                .doc("Specifies the registry name as 'APNIC'.")
                .syntax(AttributeSyntax.APNIC_REGISTRY_NAME_SYNTAX));

        put(new AttributeTypeBuilderImpl("refer", "rf", Enum.APNIC_REFER)
                .doc("The referral type, hostname and port that the server " +
                        "should use to redirect the query when using referral mechanism " +
                        "for lookups for domain objects.")
                .syntax(AttributeSyntax.APNIC_REFER_SYNTAX));

        // Not in current attribute.xml
        put(new AttributeTypeBuilderImpl("sub-dom", "sb", Enum.APNIC_SUB_DOM)
                .doc("Specifies Domain name as in RFC 1034 without trailing dot (\".\").")
                .syntax(AttributeSyntax.APNIC_SUBDOMAIN_NAME_SYNTAX));

        // Unused attribute - included to allow the code to function.
        put(new AttributeTypeBuilderImpl("assignment-size", "ae", Enum.ASSIGNMENT_SIZE)
                .doc("This attribute is not to be used.")
                .syntax(AttributeSyntax.NUMBER_SYNTAX));

        put(new AttributeTypeBuilderImpl("as-block", "ak", Enum.AS_BLOCK)
                .doc("Range of AS numbers.")
                .syntax(AttributeSyntax.AS_BLOCK_SYNTAX));

        put(new AttributeTypeBuilderImpl("as-name", "aa", Enum.AS_NAME)
                .doc("A descriptive name associated with an AS.")
                .syntax(AttributeSyntax.OBJECT_NAME_SYNTAX));

        put(new AttributeTypeBuilderImpl("as-set", "as", Enum.AS_SET)
                .doc("Defines the name of the set.")
                .syntax(AttributeSyntax.AS_SET_SYNTAX));

        put(new AttributeTypeBuilderImpl("auth", "at", Enum.AUTH)
                .doc("Defines an authentication scheme to be used.")
                .syntax(AttributeSyntax.AUTH_SCHEME_SYNTAX)
                .references(ObjectType.KEY_CERT));

        // Unused attribute - included to allow the code to function.
        put(new AttributeTypeBuilderImpl("author", "ah", Enum.AUTHOR)
                .doc("This attribute is not to be used.")
                .syntax(AttributeSyntax.NIC_HANDLE_SYNTAX)
                .references(ObjectType.PERSON, ObjectType.ROLE));

        put(new AttributeTypeBuilderImpl("aut-num", "an", Enum.AUT_NUM)
                .doc("The autonomous system number.")
                .syntax(AttributeSyntax.AS_NUMBER_SYNTAX));

        put(new AttributeTypeBuilderImpl("certif", "ce", Enum.CERTIF)
                .doc("Contains the public key.")
                .syntax(AttributeSyntax.APNIC_PUBLIC_KEY_SYNTAX));

        put(new AttributeTypeBuilderImpl("changed", "ch", Enum.CHANGED)
                .doc("The email address of who last updated the object and the date it occurred.")
                .syntax(AttributeSyntax.CHANGED_SYNTAX));

            put(new AttributeTypeBuilderImpl("components", "co", Enum.COMPONENTS)
                    .doc("Defines what component routes are used to form the aggregate.")
                    .syntax(AttributeSyntax.COMPONENTS_SYNTAX));

        put(new AttributeTypeBuilderImpl("country", "cy", Enum.COUNTRY)
                .doc("Identifies the country associated with the object.")
                .syntax(AttributeSyntax.COUNTRY_CODE_SYNTAX));

        put(new AttributeTypeBuilderImpl("default", "df", Enum.DEFAULT)
                .doc("The peer network the AS will use for as default, that is, when " +
                        "the AS has no more-specific information on where to send the " +
                        "traffic.")
                .syntax(AttributeSyntax.DEFAULT_SYNTAX));

        put(new AttributeTypeBuilderImpl("descr", "de", Enum.DESCR)
                .doc("A short decription related to the object. The description should " +
                        "include details of the network responsible for the object.")
                .syntax(AttributeSyntax.FREE_FORM_SYNTAX));

        put(new AttributeTypeBuilderImpl("domain", "dn", Enum.DOMAIN)
                .doc("Reverse delegation domain name.")
                .syntax(AttributeSyntax.DOMAIN_SYNTAX));

        put(new AttributeTypeBuilderImpl("ds-rdata", "ds", Enum.DS_RDATA)
                .doc("DS records for this domain.")
                .syntax(AttributeSyntax.DS_RDATA_SYNTAX));

        put(new AttributeTypeBuilderImpl("encryption", "en", Enum.ENCRYPTION)
                .doc("References a key-cert object representing a CSIRT public key " +
                        "used to encrypt correspondence sent to the CSIRT.")
                .syntax(AttributeSyntax.KEY_CERT_SYNTAX)
                .references(ObjectType.KEY_CERT));

        put(new AttributeTypeBuilderImpl("e-mail", "em", Enum.E_MAIL)
                .doc("A contact e-mail address. " +
                        "This attribute is filtered from the default whois output when " +
                        "at least one of the objects returned by the query contains " +
                        "an abuse-mailbox attribute.")
                .syntax(AttributeSyntax.EMAIL_SYNTAX));

        put(new AttributeTypeBuilderImpl("export", "ex", Enum.EXPORT)
                .doc("The outbound IPv4 routing policy of the AS.")
                .syntax(AttributeSyntax.EXPORT_SYNTAX));

        put(new AttributeTypeBuilderImpl("export-comps", "ec", Enum.EXPORT_COMPS)
                .doc("Defines the set's policy filter, a logical expression which " +
                        "when applied to a set of routes returns a subset of these routes.")
                .syntax(AttributeSyntax.EXPORT_COMPS_SYNTAX));

        put(new AttributeTypeBuilderImpl("fax-no", "fx", Enum.FAX_NO)
                .doc("A contact fax number.")
                .syntax(AttributeSyntax.PHONE_SYNTAX));

        put(new AttributeTypeBuilderImpl("filter", "fi", Enum.FILTER)
                .doc("Defines the set's IPv4 policy filter.")
                .syntax(AttributeSyntax.FILTER_SYNTAX));

        put(new AttributeTypeBuilderImpl("filter-set", "fs", Enum.FILTER_SET)
                .doc("Defines the name of the filter.")
                .syntax(AttributeSyntax.FILTER_SET_SYNTAX));

        put(new AttributeTypeBuilderImpl("fingerpr", "fp", Enum.FINGERPR)
                .doc("A fingerprint of a key certificate generated by the database. " +
                        "This attribute is generated automatically by the database software " +
                        "and must be omitted from the template when creating a key-cert " +
                        "object.")
                .syntax(AttributeSyntax.APNIC_FINGERPR_SYNTAX));

        // Unused attribute - included to allow the code to function.
        put(new AttributeTypeBuilderImpl("form", "fr", Enum.FORM)
                .doc("This attribute is not to be used.")
                .syntax(AttributeSyntax.POETIC_FORM_SYNTAX)
                .references(ObjectType.POETIC_FORM)
                .listValue());

        put(new AttributeTypeBuilderImpl("geoloc", "gl", Enum.GEOLOC)
                .doc("The location coordinates for the resource.")
                .syntax(AttributeSyntax.GEOLOC_SYNTAX));

        put(new AttributeTypeBuilderImpl("holes", "ho", Enum.HOLES)
                .doc("Lists the component address prefixes that are not reachable through the aggregate route" +
                        "(perhaps that part of the address space is unallocated).")
                .syntax(AttributeSyntax.HOLES_SYNTAX)
                .listValue());

        put(new AttributeTypeBuilderImpl("ifaddr", "if", Enum.IFADDR)
                .doc("Specifies an IPv4 interface address within an Internet router.")
                .syntax(AttributeSyntax.IFADDR_SYNTAX));

        put(new AttributeTypeBuilderImpl("import", "ip", Enum.IMPORT)
                .doc("The inbound IPv4 routing policy of the AS.")
                .syntax(AttributeSyntax.IMPORT_SYNTAX));

        put(new AttributeTypeBuilderImpl("inet6num", "i6", Enum.INET6NUM)
                .doc("The range of IPv6 addresses, in prefix notation, the inet6num object.")
                .syntax(AttributeSyntax.IPV6_SYNTAX));

        put(new AttributeTypeBuilderImpl("inetnum", "in", Enum.INETNUM)
                .doc("The range of IPv4 address space the inetnum object presents.")
                .syntax(AttributeSyntax.IPV4_SYNTAX));

        put(new AttributeTypeBuilderImpl("inet-rtr", "ir", Enum.INET_RTR)
                .doc("Fully qualified DNS name of the inet-rtr without trailing dot (\".\").")
                .syntax(AttributeSyntax.INET_RTR_SYNTAX));

        // supports inject-rt, inject-r6 in attribute.xml
        // .doc is same as in attribute.xml
        put(new AttributeTypeBuilderImpl("inject", "ij", Enum.INJECT)
                .doc("Specifies which routers perform the aggregation and when they perform it.")
                .syntax(AttributeSyntax.INJECT_SYNTAX));

        put(new AttributeTypeBuilderImpl("interface", "ie", Enum.INTERFACE)
                .doc("Specifies a multiprotocol (IPv4 or IPv6) interface address within an Internet router.")
                .syntax(AttributeSyntax.INTERFACE_SYNTAX));

        put(new AttributeTypeBuilderImpl("irt", "it", Enum.IRT)
                .doc("Specifies the name of the irt object. The name should start with the prefix \"IRT-\", " +
                        "which is reserved for this type of object.")
                .syntax(AttributeSyntax.IRT_SYNTAX));

        put(new AttributeTypeBuilderImpl("irt-nfy", "iy", Enum.IRT_NFY)
                .doc("The e-mail address to be notified when a reference to the irt object is added or removed.")
                .syntax(AttributeSyntax.EMAIL_SYNTAX));

        put(new AttributeTypeBuilderImpl("key-cert", "kc", Enum.KEY_CERT)
                .doc("Defines the public key stored in the database.")
                .syntax(AttributeSyntax.KEY_CERT_SYNTAX));

        put(new AttributeTypeBuilderImpl("language", "ln", Enum.LANGUAGE)
                .doc("Identifies the language.")
                .syntax(AttributeSyntax.LANGUAGE_CODE_SYNTAX));

        put(new AttributeTypeBuilderImpl("local-as", "la", Enum.LOCAL_AS)
                .doc("Specifies the autonomous system that operates the router.")
                .syntax(AttributeSyntax.AS_NUMBER_SYNTAX));

        put(new AttributeTypeBuilderImpl("mbrs-by-ref", "mr", Enum.MBRS_BY_REF)
                .doc("Allows indirect population of the set. If the mbrs-by-ref " +
                        "attribute is missing, the set is defined explicitly by the " +
                        "members attribute.")
                .syntax(AttributeSyntax.MBRS_BY_REF_SYNTAX)
                .references(ObjectType.MNTNER)
                .listValue());

        // Uses members for members-as and members-is hence left RIPE's .doc
        // Change .doc as per attribute.xml
        put(new AttributeTypeBuilderImpl("members", "ms", Enum.MEMBERS)
                .doc(new Multiple(new HashMap<ObjectType, String>() {{
                    put(ObjectType.RTR_SET, "Lists the members of the rtr_set.");
                    put(ObjectType.AS_SET, "Lists the members of the as_set.");
                }}))
                .syntax(AttributeSyntax.MEMBERS_SYNTAX)
                .listValue()); // No reference checking should be performed for members!

        // Supports member-of-ir, member-of-rt, member-of-an in attribute.xml
        // Changed .doc as per attribute.xml
        put(new AttributeTypeBuilderImpl("member-of", "mo", Enum.MEMBER_OF)
                .doc("Identifies any rtr-set objects this router wants to be a member " +
                        "This claim, however, should be acknowledged by a respective " +
                        "mbrs-by-ref attribute in the referenced rtr-set object.")
                .syntax(AttributeSyntax.MEMBER_OF_SYNTAX)
                .references(ObjectType.AS_SET, ObjectType.ROUTE_SET, ObjectType.RTR_SET)
                .listValue());

        put(new AttributeTypeBuilderImpl("method", "mh", Enum.METHOD)
                .doc("The type of the public key.")
                .syntax(AttributeSyntax.METHOD_SYNTAX));

        put(new AttributeTypeBuilderImpl("mntner", "mt", Enum.MNTNER)
                .doc("A unique identifier of the mntner object.")
                .syntax(AttributeSyntax.OBJECT_NAME_SYNTAX));

        put(new AttributeTypeBuilderImpl("mnt-by", "mb", Enum.MNT_BY)
                .doc("Lists a registered mntner used to authorise and authenticate changes to this object.")
                .syntax(AttributeSyntax.OBJECT_NAME_SYNTAX)
                .references(ObjectType.MNTNER)
                .listValue());

        put(new AttributeTypeBuilderImpl("mnt-domains", "md", Enum.MNT_DOMAINS)
                .doc("Specifies the identifier of a registered mntner object used for " +
                        "reverse domain authorisation. Protects domain objects. The " +
                        "authentication method of this maintainer object will be used for " +
                        "any encompassing reverse domain object.")
                .syntax(AttributeSyntax.OBJECT_NAME_SYNTAX)
                .references(ObjectType.MNTNER)
                .listValue());

        put(new AttributeTypeBuilderImpl("mnt-irt", "mi", Enum.MNT_IRT)
                .doc("The identifier of an irt object representing a Computer Security " +
                        "Incident Response Team (CSIRT) that handles security incidents for " +
                        "the IP address range specified in this object.")
                .syntax(AttributeSyntax.IRT_SYNTAX)
                .references(ObjectType.IRT)
                .listValue());

        put(new AttributeTypeBuilderImpl("mnt-lower", "ml", Enum.MNT_LOWER)
                .doc("Lists a registered mntner used to authorise and authenticate the " +
                        "creation of any object more specific than this object.\n" +
                        "\n" +
                        "Note:\n" +
                        "\n" +
                        "Mnt-lower can be used to authorise and authenticate the creation " +
                        "of route and route6 objects if  mnt-routes is not specified in the " +
                        "aut-num object or in a less specific inetnum, inet6num, route or" +
                        "route6 object.")
                .syntax(AttributeSyntax.OBJECT_NAME_SYNTAX)
                .references(ObjectType.MNTNER)
                .listValue());

        put(new AttributeTypeBuilderImpl("mnt-nfy", "mn", Enum.MNT_NFY)
                .doc("Specifies the e-mail address to be notified when an object " +
                        "protected by a mntner is successfully updated.")
                .syntax(AttributeSyntax.EMAIL_SYNTAX));

        put(new AttributeTypeBuilderImpl("mnt-ref", "mz", Enum.MNT_REF)
                .doc("Specifies the maintainer objects that are entitled to add references to " +
                        "the organisation object from other objects.")
                .syntax(AttributeSyntax.OBJECT_NAME_SYNTAX)
                .references(ObjectType.MNTNER)
                .listValue());

        // Supports mnt-routes, mnt-routes6, mnt-routes-an in attribute.xml
        // Need to review the .doc for each object and change as per APNIC context
        put(new AttributeTypeBuilderImpl("mnt-routes", "mu", Enum.MNT_ROUTES)
                .doc(new Documented.Multiple(new HashMap<ObjectType, String>() {{
                    put(ObjectType.AUT_NUM, "" +
                            "This attribute references a maintainer object which is used in\n" +
                            "determining authorisation for the creation of route6 objects.\n" +
                            "This entry is for the mnt-routes attribute of aut-num class.\n" +
                            "After the reference to the maintainer, an optional list of\n" +
                            "prefix ranges inside of curly braces or the keyword \"ANY\" may\n" +
                            "follow. The default, when no additional set items are\n" +
                            "specified, is \"ANY\" or all more specifics.");

                    put(ObjectType.INET6NUM, "" +
                            "This attribute references a maintainer object which is used in\n" +
                            "determining authorisation for the creation of route6 objects.\n" +
                            "This entry is for the mnt-routes attribute of route6 and inet6num classes.\n" +
                            "After the reference to the maintainer, an optional list of\n" +
                            "prefix ranges inside of curly braces or the keyword \"ANY\" may\n" +
                            "follow. The default, when no additional set items are\n" +
                            "specified, is \"ANY\" or all more specifics.");

                    put(ObjectType.INETNUM, "" +
                            "This attribute references a maintainer object which is used in\n" +
                            "determining authorisation for the creation of route objects.\n" +
                            "After the reference to the maintainer, an optional list of\n" +
                            "prefix ranges inside of curly braces or the keyword \"ANY\" may\n" +
                            "follow. The default, when no additional set items are\n" +
                            "specified, is \"ANY\" or all more specifics. Please refer to\n" +
                            "RFC-2622 for more information.");

                    put(ObjectType.ROUTE, "" +
                            "This attribute references a maintainer object which is used in\n" +
                            "determining authorisation for the creation of route objects.\n" +
                            "After the reference to the maintainer, an optional list of\n" +
                            "prefix ranges inside of curly braces or the keyword \"ANY\" may\n" +
                            "follow. The default, when no additional set items are\n" +
                            "specified, is \"ANY\" or all more specifics. Please refer to\n" +
                            "RFC-2622 for more information.");

                    put(ObjectType.ROUTE6, "" +
                            "This attribute references a maintainer object which is used in\n" +
                            "determining authorisation for the creation of route6 objects.\n" +
                            "This entry is for the mnt-routes attribute of route6 and inet6num classes.\n" +
                            "After the reference to the maintainer, an optional list of\n" +
                            "prefix ranges inside of curly braces or the keyword \"ANY\" may\n" +
                            "follow. The default, when no additional set items are\n" +
                            "specified, is \"ANY\" or all more specifics.");

                }}))
                .syntax(AttributeSyntax.MNT_ROUTES_SYNTAX)
                .references(ObjectType.MNTNER));

        put(new AttributeTypeBuilderImpl("mp-default", "ma", Enum.MP_DEFAULT)
                .doc("Specifies default multiprotocol (IPv4 and IPv6) routing policies.")
                .syntax(AttributeSyntax.MP_DEFAULT_SYNTAX));

        put(new AttributeTypeBuilderImpl("mp-export", "me", Enum.MP_EXPORT)
                .doc("The outbound (IPv4 or IPv6) routing policy of the AS.")
                .syntax(AttributeSyntax.MP_EXPORT_SYNTAX));

        put(new AttributeTypeBuilderImpl("mp-filter", "mf", Enum.MP_FILTER)
                .doc("Defines the set's multiprotocol (IPv4 and IPv6) policy filter.")
                .syntax(AttributeSyntax.MP_FILTER_SYNTAX));

        put(new AttributeTypeBuilderImpl("mp-import", "my", Enum.MP_IMPORT)
                .doc("The inbound multiprotocol (IPv4 or IPv6) routing policy of the AS.")
                .syntax(AttributeSyntax.MP_IMPORT_SYNTAX));

        // Supports mp-members-is and mep-members-as as in attribute.xml
        put(new AttributeTypeBuilderImpl("mp-members", "mm", Enum.MP_MEMBERS)
                .doc(new Multiple(new HashMap<ObjectType, String>() {{
                    put(ObjectType.RTR_SET, "Lists the multiprotocol (IPv4 or IPv6) members of the rtr-set.");
                    put(ObjectType.ROUTE_SET, "Lists the multiprotocol (IPv4 or IPv6) members of the route-set.");
                }}))
                .syntax(AttributeSyntax.MP_MEMBERS_SYNTAX).listValue());

        put(new AttributeTypeBuilderImpl("mp-peer", "mp", Enum.MP_PEER)
                .doc(new Multiple(new HashMap<ObjectType, String>() {{
                    put(ObjectType.INET_RTR, "Details of any (interior or exterior) multiprotocol (IPv4 and IPv6) router peerings.");
                    put(ObjectType.PEERING_SET, "Defines a multiprotocol peering that can be used for importing or exporting routes.");
                }}))
                .syntax(AttributeSyntax.MP_PEER_SYNTAX));

        put(new AttributeTypeBuilderImpl("mp-peering", "mg", Enum.MP_PEERING)
                .doc("Defines a multiprotocol (IPv4 or IPv6) peering that can be used for importing or exporting routes.\n" +
                        "\n" +
                        "NOTE: Although the mp-peering attribute is optional, at least one " +
                        "peering or mp-peering must be present in the peering-set object.")
                .syntax(AttributeSyntax.MP_PEERING_SYNTAX));

        put(new AttributeTypeBuilderImpl("netname", "na", Enum.NETNAME)
                .doc("The name of a range of IP address space.")
                .syntax(AttributeSyntax.NETNAME_SYNTAX));

        put(new AttributeTypeBuilderImpl("nic-hdl", "nh", Enum.NIC_HDL)
                .doc("The NIC-handle of a person object. When creating an " +
                        "object, set the value of the attribute to either:\n" +
                        "\n" +
                        "- AUTO-1\n" +
                        "\n" +
                        "The database will generate the NIC-handle based on the " +
                        "initials of the name in the person or role attribute.\n" +
                        "\n" +
                        "- AUTO-1<initials>\n" +
                        "\n" +
                        "The database will generate a NIC-handle based on the " +
                        "initials specified.")
                .syntax(AttributeSyntax.NIC_HANDLE_SYNTAX));

        put(new AttributeTypeBuilderImpl("notify", "ny", Enum.NOTIFY)
                .doc("Specifies the e-mail address to which notifications of changes " +
                        "to this object should be sent. " +
                        "This attribute is filtered from the default whois output.")
                .syntax(AttributeSyntax.EMAIL_SYNTAX));

        put(new AttributeTypeBuilderImpl("nserver", "ns", Enum.NSERVER)
                .doc("The nameservers of the domain. A minimum of two is mandatory.")
                .syntax(AttributeSyntax.NSERVER_SYNTAX));

        // No APNIC .doc
        put(new AttributeTypeBuilderImpl("org", "og", Enum.ORG)
                .doc("Points to an existing organisation object representing the entity that holds the resource.")
                .syntax(AttributeSyntax.ORGANISATION_SYNTAX)
                .references(ObjectType.ORGANISATION));

        put(new AttributeTypeBuilderImpl("org-name", "on", Enum.ORG_NAME)
                .doc("Specifies the name of the organisation that this organisation object represents in the whois" +
                        "database. This is an ASCII-only text attribute. The restriction is because this attribute is" +
                        "a look-up key and the whois protocol does not allow specifying character sets in queries. " +
                        "The user can put the name of the organisation in non-ASCII character sets in " +
                        "the \"descr:\" attribute if required.")
                .syntax(AttributeSyntax.ORG_NAME_SYNTAX));

        put(new AttributeTypeBuilderImpl("org-type", "ot", Enum.ORG_TYPE)
                .doc("Specifies the type of the organisation.")
                .syntax(AttributeSyntax.ORG_TYPE_SYNTAX));

        put(new AttributeTypeBuilderImpl("organisation", "oa", Enum.ORGANISATION)
                .doc("Specifies the ID of an organisation object. When creating an object, one has to specify " +
                        "an \"AUTO\" ID by setting the value of the attribute to \"AUTO-1\" or \"AUTO-1<letterCombination>\", " +
                        "so the database will assign the ID automatically.")
                .syntax(AttributeSyntax.ORGANISATION_SYNTAX));

        put(new AttributeTypeBuilderImpl("origin", "or", Enum.ORIGIN)
                .doc("The AS that originates the route. The corresponding " +
                        "aut-num object should be registered in the database.")
                .syntax(AttributeSyntax.AS_NUMBER_SYNTAX)
                .references(ObjectType.AUT_NUM));

        put(new AttributeTypeBuilderImpl("owner", "ow", Enum.OWNER)
                .doc("Specifies the owner of the public key.")
                .syntax(AttributeSyntax.GENERATED_SYNTAX));

        put(new AttributeTypeBuilderImpl("peer", "pe", Enum.PEER)
                .doc("Details of any (interior or exterior) router peerings.")
                .syntax(AttributeSyntax.PEER_SYNTAX));

        put(new AttributeTypeBuilderImpl("peering", "pg", Enum.PEERING)
                .doc("Defines a peering that can be used for importing or exporting IPv4 routes. \n" +
                        "\n" +
                        "NOTE: Although the peering attribute is optional, at least one " +
                        "peering or mp-peering must be present in the peering-set object.")
                .syntax(AttributeSyntax.PEERING_SYNTAX));

        put(new AttributeTypeBuilderImpl("peering-set", "ps", Enum.PEERING_SET)
                .doc("Specifies the name of the peering-set.")
                .syntax(AttributeSyntax.PEERING_SET_SYNTAX));

        put(new AttributeTypeBuilderImpl("person", "pn", Enum.PERSON)
                .doc("The full name of an administrative, technical or zone contact person for " +
                        "other objects in the database.")
                .syntax(AttributeSyntax.PERSON_ROLE_NAME_SYNTAX));

        put(new AttributeTypeBuilderImpl("phone", "ph", Enum.PHONE)
                .doc("A contact telephone number.")
                .syntax(AttributeSyntax.PHONE_SYNTAX));

        // Not in current attribute.xml
        put(new AttributeTypeBuilderImpl("ping-hdl", "pc", Enum.PING_HDL)
                .doc("References a person or role capable of responding to queries concerning the IP address(es) " +
                        "specified in the 'pingable' attribute.")
                .syntax(AttributeSyntax.NIC_HANDLE_SYNTAX)
                .references(ObjectType.PERSON, ObjectType.ROLE));

        //Not in current attribute.xml
        put(new AttributeTypeBuilderImpl("pingable", "pa", Enum.PINGABLE)
                .doc("Allows a network operator to advertise an IP address of a node that should be reachable from outside " +
                        "networks. This node can be used as a destination address for diagnostic tests. " +
                        "The IP address must be within the address range of the prefix containing this attribute.")
                .syntax(AttributeSyntax.PINGABLE_SYNTAX));

        // Poem is obsolete in APNIC context. Removing this is beaking. It should be removed
        put(new AttributeTypeBuilderImpl("poem", "po", Enum.POEM)
                .doc("This attribute is not to be used.")
                .syntax(AttributeSyntax.POEM_SYNTAX));

        // POETIC_FORM is obsolete in APNIC context. Removing this is beaking. It should be removed
        put(new AttributeTypeBuilderImpl("poetic-form", "pf", Enum.POETIC_FORM)
                .doc("This attribute is not to be used.")
                .syntax(AttributeSyntax.POETIC_FORM_SYNTAX));

        put(new AttributeTypeBuilderImpl("referral-by", "rb", Enum.REFERRAL_BY)
                .doc("This attribute is required in the mntner object. It may " +
                        "never be altered after the addition of the mntner. This " +
                        "attribute refers to the mntner that created this " +
                        "mntner. It may be multiple if more than one signature " +
                        "appeared on the transaction creating the object.")
                .syntax(AttributeSyntax.APNIC_REFERRAL_BY_SYNTAX)
                .references(ObjectType.MNTNER));

        put(new AttributeTypeBuilderImpl("ref-nfy", "rn", Enum.REF_NFY)
                .doc("Specifies the e-mail address to be notified when a reference " +
                        "to the organisation object is added or removed. " +
                        "This attribute is filtered from the default whois output when at " +
                        "least one of the objects returned by the query contains an " +
                        "abuse-mailbox attribute.")
                .syntax(AttributeSyntax.EMAIL_SYNTAX));

        put(new AttributeTypeBuilderImpl("remarks", "rm", Enum.REMARKS)
                .doc("Information about the object that cannot be stated in other " +
                        "attributes.")
                .syntax(AttributeSyntax.FREE_FORM_SYNTAX));

        put(new AttributeTypeBuilderImpl("role", "ro", Enum.ROLE)
                .doc("The full name of a role entity.")
                .syntax(AttributeSyntax.PERSON_ROLE_NAME_SYNTAX));

        put(new AttributeTypeBuilderImpl("route", "rt", Enum.ROUTE)
                .doc("The prefix of the interAS route. Together with the origin " +
                        "attribute, it forms the primary key of the route object.")
                .syntax(AttributeSyntax.ROUTE_SYNTAX));

        put(new AttributeTypeBuilderImpl("route6", "r6", Enum.ROUTE6)
                .doc("The IPv6 prefix of the interAS route. Together with the origin attribute, " +
                        "constitutes a primary key of the route6 object.")
                .syntax(AttributeSyntax.ROUTE6_SYNTAX));

        put(new AttributeTypeBuilderImpl("route-set", "rs", Enum.ROUTE_SET)
                .doc("Specifies the name of the route-set.")
                .syntax(AttributeSyntax.ROUTE_SET_SYNTAX));

        put(new AttributeTypeBuilderImpl("rtr-set", "is", Enum.RTR_SET)
                .doc("Defines the name of the rtr-set.")
                .syntax(AttributeSyntax.RTR_SET_SYNTAX));

        put(new AttributeTypeBuilderImpl("signature", "sg", Enum.SIGNATURE)
                .doc("References a key-cert object representing a CSIRT public key " +
                        "used by the team to sign their correspondence.")
                .syntax(AttributeSyntax.KEY_CERT_SYNTAX)
                .references(ObjectType.KEY_CERT));

        put(new AttributeTypeBuilderImpl("source", "so", Enum.SOURCE)
                .doc("The database where the object is registered.")
                .syntax(AttributeSyntax.SOURCE_SYNTAX));

        // Working for both status-in and status-i6 xmlnames.
        put(new AttributeTypeBuilderImpl("status", "st", Enum.STATUS)
                .doc("The status of the address range represented by inetnum or inet6num " +
                        "object.")
                .syntax(AttributeSyntax.STATUS_SYNTAX));

        put(new AttributeTypeBuilderImpl("tech-c", "tc", Enum.TECH_C)
                .doc("The NIC-handle of a technical contact.")
                .syntax(AttributeSyntax.NIC_HANDLE_SYNTAX)
                .references(ObjectType.PERSON, ObjectType.ROLE));

        // Text is obsolete in APNIC context, removing this is breaking. This should be removed later
        put(new AttributeTypeBuilderImpl("text", "tx", Enum.TEXT)
                .doc("Text of the limerick. Must be humorous, but not malicious or insulting.")
                .syntax(AttributeSyntax.FREE_FORM_SYNTAX));

        put(new AttributeTypeBuilderImpl("upd-to", "dt", Enum.UPD_TO)
                .doc("The e-mail address to be notified when an object protected by " +
                        "a mntner is unsuccessfully updated.")
                .syntax(AttributeSyntax.EMAIL_SYNTAX));

        put(new AttributeTypeBuilderImpl("zone-c", "zc", Enum.ZONE_C)
                .doc("The NIC-handle of a zone contact.")
                .syntax(AttributeSyntax.NIC_HANDLE_SYNTAX)
                .references(ObjectType.PERSON, ObjectType.ROLE));
    }

    private static void put(AttributeTypeBuilderImpl entry) {
        // Test for duplicates
        if (localMap.put(entry.getEnumType(), entry) != null) {
            throw new BeanInitializationException("Attribute Type duplicate mapping exception: " + entry.getEnumType());
        }
    }

    private final String name;
    private final String flag;
    private Documented description;
    private AttributeSyntax syntax = AttributeSyntax.ANY_SYNTAX;
    private AttributeValueType valueType = AttributeValueType.SINGLE_VALUE;
    private Set<ObjectType> references = Collections.emptySet();
    private Enum enumType;

    public AttributeTypeBuilderImpl(final String name, final String flag, final Enum enumType) {
        this.name = name;
        this.flag = flag;
        this.enumType = enumType;
    }

    public AttributeTypeBuilderImpl doc(final String description) {
        this.description = new Single(description);
        return this;
    }

    public AttributeTypeBuilderImpl doc(final Documented description) {
        this.description = description;
        return this;
    }

    public AttributeTypeBuilderImpl syntax(final AttributeSyntax attributeSyntax) {
        this.syntax = attributeSyntax;
        return this;
    }

    public AttributeTypeBuilderImpl listValue() {
        this.valueType = LIST_VALUE;
        return this;
    }

    public AttributeTypeBuilderImpl references(final ObjectType... objectTypes) {
        this.references = Collections.unmodifiableSet(Sets.newEnumSet(Lists.newArrayList(objectTypes), ObjectType.class));
        return this;
    }


    public String getName() {
        return name == null ? "" : name;
    }

    public String getFlag() {
        return flag == null ? "" : flag;
    }

    public Documented getDescription() {
        return description;
    }

    @Override
    public String getDescription(final ObjectType objectType) {
        return description.getDescription(objectType);
    }

    public AttributeSyntax getSyntax() {
        return syntax;
    }

    public AttributeValueType getValueType() {
        return valueType;
    }

    public Set<ObjectType> getReferences() {
        return references;
    }

    public Enum getEnumType() {
        return enumType;
    }

    public Map<Enum, AttributeTypeBuilder> getAttributeTypeBuilderMap() {
        return localMap;
    }

    public boolean isImplemented() {
        return enumType != null;
    }

}

