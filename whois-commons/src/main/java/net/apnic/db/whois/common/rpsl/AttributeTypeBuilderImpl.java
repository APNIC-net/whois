package net.apnic.db.whois.common.rpsl;

import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import net.ripe.db.whois.common.rpsl.AttributeSyntax;
import net.ripe.db.whois.common.rpsl.AttributeTypeBuilder;
import net.ripe.db.whois.common.rpsl.AttributeValueType;
import net.ripe.db.whois.common.rpsl.Documented;
import net.ripe.db.whois.common.rpsl.ObjectType;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static net.ripe.db.whois.common.rpsl.AttributeValueType.LIST_VALUE;

public class AttributeTypeBuilderImpl implements AttributeTypeBuilder {
    static Map<Enum, AttributeTypeBuilder> localMap = new HashMap<Enum, AttributeTypeBuilder>();

    static {
        mapHelperAdd(new AttributeTypeBuilderImpl("abuse-mailbox", "am", Enum.ABUSE_MAILBOX)
                .doc("Specifies the e-mail address to which abuse complaints should be sent. " +
                        "This attribute should only be used in the ROLE object. It will be deprecated from any other object. " +
                        "Adding this attribute to a ROLE object, then referencing it in an \"abuse-c:\" attribute of an ORGANISATION object, " +
                        "will remove any query limits for the ROLE object. These ROLE objects are considered to include only commercial data.")
                .syntax(AttributeSyntax.EMAIL_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("abuse-c", "au", Enum.ABUSE_C)
                .doc("References an abuse contact. " +
                        "This can only be a ROLE object containing an \"abuse-mailbox:\" attribute. " +
                        "Making this reference will remove any query limits for the ROLE object. " +
                        "These ROLE objects are considered to include only commercial data.")
                .syntax(AttributeSyntax.NIC_HANDLE_SYNTAX)
                .references(ObjectType.ROLE));


        mapHelperAdd(new AttributeTypeBuilderImpl("address", "ad", Enum.ADDRESS)
                .doc("Full postal address of a contact")
                .syntax(AttributeSyntax.FREE_FORM_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("admin-c", "ac", Enum.ADMIN_C)
                .doc("References an on-site administrative contact.")
                .syntax(AttributeSyntax.NIC_HANDLE_SYNTAX)
                .references(ObjectType.PERSON, ObjectType.ROLE));

        mapHelperAdd(new AttributeTypeBuilderImpl("aggr-bndry", "ab", Enum.AGGR_BNDRY)
                .doc("Defines a set of ASes, which form the aggregation boundary.")
                .syntax(AttributeSyntax.AGGR_BNDRY_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("aggr-mtd", "ag", Enum.AGGR_MTD)
                .doc("Specifies how the aggregate is generated.")
                .syntax(AttributeSyntax.AGGR_MTD_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("alias", "az", Enum.ALIAS)
                .doc("The canonical DNS name for the router.")
                .syntax(AttributeSyntax.ALIAS_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("assignment-size", "ae", Enum.ASSIGNMENT_SIZE)
                .doc("Specifies the size of blocks assigned to end users from this aggregated inet6num assignment.")
                .syntax(AttributeSyntax.NUMBER_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("as-block", "ak", Enum.AS_BLOCK)
                .doc("Range of AS numbers.")
                .syntax(AttributeSyntax.AS_BLOCK_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("as-name", "aa", Enum.AS_NAME)
                .doc("A descriptive name associated with an AS.")
                .syntax(AttributeSyntax.OBJECT_NAME_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("as-set", "as", Enum.AS_SET)
                .doc("Defines the name of the set.")
                .syntax(AttributeSyntax.AS_SET_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("auth", "at", Enum.AUTH)
                .doc("Defines an authentication scheme to be used.")
                .syntax(AttributeSyntax.AUTH_SCHEME_SYNTAX)
                .references(ObjectType.KEY_CERT));

        mapHelperAdd(new AttributeTypeBuilderImpl("author", "ah", Enum.AUTHOR)
                .doc("References a poem author.")
                .syntax(AttributeSyntax.NIC_HANDLE_SYNTAX)
                .references(ObjectType.PERSON, ObjectType.ROLE));

        mapHelperAdd(new AttributeTypeBuilderImpl("aut-num", "an", Enum.AUT_NUM)
                .doc("The autonomous system number.")
                .syntax(AttributeSyntax.AS_NUMBER_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("certif", "ce", Enum.CERTIF)
                .doc("Contains the public key.")
                .syntax(AttributeSyntax.CERTIF_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("changed", "ch", Enum.CHANGED)
                .doc("Specifies who submitted the update, and when the object was updated. " +
                        "This attribute is filtered from the default whois output.")
                .syntax(AttributeSyntax.CHANGED_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("components", "co", Enum.COMPONENTS)
                .doc("The \"components:\" attribute defines what component routes are used to form the aggregate.")
                .syntax(AttributeSyntax.COMPONENTS_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("country", "cy", Enum.COUNTRY)
                .doc("Identifies the country.")
                .syntax(AttributeSyntax.COUNTRY_CODE_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("default", "df", Enum.DEFAULT)
                .doc("Specifies default routing policies.")
                .syntax(AttributeSyntax.DEFAULT_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("descr", "de", Enum.DESCR)
                .doc("A short decription related to the object.")
                .syntax(AttributeSyntax.FREE_FORM_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("domain", "dn", Enum.DOMAIN)
                .doc("Domain name.")
                .syntax(AttributeSyntax.DOMAIN_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("ds-rdata", "ds", Enum.DS_RDATA)
                .doc("DS records for this domain.")
                .syntax(AttributeSyntax.DS_RDATA_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("encryption", "en", Enum.ENCRYPTION)
                .doc("References a key-cert object representing a CSIRT public key used " +
                        "to encrypt correspondence sent to the CSIRT.")
                .syntax(AttributeSyntax.KEY_CERT_SYNTAX)
                .references(ObjectType.KEY_CERT));

        mapHelperAdd(new AttributeTypeBuilderImpl("export", "ex", Enum.EXPORT)
                .doc("Specifies an export policy expression.")
                .syntax(AttributeSyntax.EXPORT_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("export-comps", "ec", Enum.EXPORT_COMPS)
                .doc("Defines the set's policy filter, a logical expression which when applied to a set of " +
                        "routes returns a subset of these routes.")
                .syntax(AttributeSyntax.EXPORT_COMPS_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("e-mail", "em", Enum.E_MAIL)
                .doc("The e-mail address of a person, role, organisation or irt team. " +
                        "This attribute is filtered from the default whois output when at least one of the objects " +
                        "returned by the query contains an abuse-mailbox attribute.")
                .syntax(AttributeSyntax.EMAIL_SYNTAX));


        mapHelperAdd(new AttributeTypeBuilderImpl("fax-no", "fx", Enum.FAX_NO)
                .doc("The fax number of a contact.")
                .syntax(AttributeSyntax.PHONE_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("filter", "fi", Enum.FILTER)
                .doc("Defines the set's policy filter.")
                .syntax(AttributeSyntax.FILTER_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("filter-set", "fs", Enum.FILTER_SET)
                .doc("Defines the name of the filter.")
                .syntax(AttributeSyntax.FILTER_SET_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("fingerpr", "fp", Enum.FINGERPR)
                .doc("A fingerprint of a key certificate generated by the database.")
                .syntax(AttributeSyntax.GENERATED_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("form", "fr", Enum.FORM)
                .doc("Specifies the identifier of a registered poem type.")
                .syntax(AttributeSyntax.POETIC_FORM_SYNTAX)
                .references(ObjectType.POETIC_FORM)
                .listValue());

        mapHelperAdd(new AttributeTypeBuilderImpl("geoloc", "gl", Enum.GEOLOC)
                .doc("The location coordinates for the resource.")
                .syntax(AttributeSyntax.GEOLOC_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("holes", "ho", Enum.HOLES)
                .doc("Lists the component address prefixes that are not reachable through the aggregate route" +
                        "(perhaps that part of the address space is unallocated).")
                .syntax(AttributeSyntax.HOLES_SYNTAX)
                .listValue());

        mapHelperAdd(new AttributeTypeBuilderImpl("ifaddr", "if", Enum.IFADDR)
                .doc("Specifies an interface address within an Internet router.")
                .syntax(AttributeSyntax.IFADDR_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("import", "ip", Enum.IMPORT)
                .doc("Specifies import policy expression.")
                .syntax(AttributeSyntax.IMPORT_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("inet6num", "i6", Enum.INET6NUM)
                .doc("Specifies a range of IPv6 addresses in prefix notation.")
                .syntax(AttributeSyntax.IPV6_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("inetnum", "in", Enum.INETNUM)
                .doc("Specifies a range of IPv4 that inetnum object presents. " +
                        "The ending address should be greater than the starting one.")
                .syntax(AttributeSyntax.IPV4_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("inet-rtr", "ir", Enum.INET_RTR)
                .doc("Fully qualified DNS name of the inet-rtr without trailing \".\".")
                .syntax(AttributeSyntax.INET_RTR_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("inject", "ij", Enum.INJECT)
                .doc("Specifies which routers perform the aggregation and when they perform it.")
                .syntax(AttributeSyntax.INJECT_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("interface", "ie", Enum.INTERFACE)
                .doc("Specifies a multiprotocol interface address within an Internet router.")
                .syntax(AttributeSyntax.INTERFACE_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("irt", "it", Enum.IRT)
                .doc("Specifies the name of the irt object. The name should start with the prefix \"IRT-\", " +
                        "reserved for this type of object.")
                .syntax(AttributeSyntax.IRT_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("irt-nfy", "iy", Enum.IRT_NFY)
                .doc("Specifies the e-mail address to be notified when a reference to the irt object is added or removed.")
                .syntax(AttributeSyntax.EMAIL_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("key-cert", "kc", Enum.KEY_CERT)
                .doc("Defines the public key stored in the database.")
                .syntax(AttributeSyntax.KEY_CERT_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("language", "ln", Enum.LANGUAGE)
                .doc("Identifies the language.")
                .syntax(AttributeSyntax.LANGUAGE_CODE_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("local-as", "la", Enum.LOCAL_AS)
                .doc("Specifies the autonomous system that operates the router.")
                .syntax(AttributeSyntax.AS_NUMBER_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("mbrs-by-ref", "mr", Enum.MBRS_BY_REF)
                .doc("This attribute can be used in all \"set\" objects; it allows indirect population of a set. " +
                        "If this attribute is used, the set also includes objects of the corresponding type " +
                        "(aut-num objects for as-set, for example) that are protected by one of these maintainers " +
                        "and whose \"member-of:\" attributes refer to the name of the set. " +
                        "If the value of a \"mbrs-by-ref:\" attribute is ANY, any object of the corresponding type " +
                        "referring to the set is a member of the set. If the \"mbrs-by-ref:\" attribute is missing, " +
                        "the set is defined explicitly by the \"members:\" attribute.")
                .syntax(AttributeSyntax.MBRS_BY_REF_SYNTAX)
                .references(ObjectType.MNTNER)
                .listValue());

        mapHelperAdd(new AttributeTypeBuilderImpl("members", "ms", Enum.MEMBERS)
                .doc("Lists the members of the set.")
                .syntax(AttributeSyntax.MEMBERS_SYNTAX)
                .listValue()); // No reference checking should be performed for members!

        mapHelperAdd(new AttributeTypeBuilderImpl("member-of", "mo", Enum.MEMBER_OF)
                .doc("This attribute can be used in the route, aut-num and inet-rtr classes. " +
                        "The value of the \"member-of:\" attribute identifies a set object that this object wants " +
                        "to be a member of. This claim, however, should be acknowledged by a " +
                        "respective \"mbrs-by-ref:\" attribute in the referenced object.")
                .syntax(AttributeSyntax.MEMBER_OF_SYNTAX)
                .references(ObjectType.AS_SET, ObjectType.ROUTE_SET, ObjectType.RTR_SET)
                .listValue());

        mapHelperAdd(new AttributeTypeBuilderImpl("method", "mh", Enum.METHOD)
                .doc("Defines the type of the public key.")
                .syntax(AttributeSyntax.METHOD_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("mntner", "mt", Enum.MNTNER)
                .doc("A unique identifier of the mntner object.")
                .syntax(AttributeSyntax.OBJECT_NAME_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("mnt-by", "mb", Enum.MNT_BY)
                .doc("Specifies the identifier of a registered mntner object used for authorisation of operations " +
                        "performed with the object that contains this attribute.")
                .syntax(AttributeSyntax.OBJECT_NAME_SYNTAX)
                .references(ObjectType.MNTNER)
                .listValue());

        mapHelperAdd(new AttributeTypeBuilderImpl("mnt-domains", "md", Enum.MNT_DOMAINS)
                .doc("Specifies the identifier of a registered mntner object used for reverse domain authorisation. " +
                        "Protects domain objects. The authentication method of this maintainer object will be used for " +
                        "any encompassing reverse domain object.")
                .syntax(AttributeSyntax.OBJECT_NAME_SYNTAX)
                .references(ObjectType.MNTNER)
                .listValue());

        mapHelperAdd(new AttributeTypeBuilderImpl("mnt-irt", "mi", Enum.MNT_IRT)
                .doc("May appear in an inetnum or inet6num object. It points to an irt object representing a " +
                        "Computer Security Incident Response Team (CSIRT) that handles security incidents for " +
                        "the address space specified by the inetnum or inet6num object.")
                .syntax(AttributeSyntax.IRT_SYNTAX)
                .references(ObjectType.IRT)
                .listValue());

        mapHelperAdd(new AttributeTypeBuilderImpl("mnt-lower", "ml", Enum.MNT_LOWER)
                .doc("Specifies the identifier of a registered mntner object used for hierarchical authorisation. " +
                        "Protects creation of objects directly (one level) below in the hierarchy of an object type. " +
                        "The authentication method of this maintainer object will then be used upon creation of any " +
                        "object directly below the object that contains the \"mnt-lower:\" attribute.")
                .syntax(AttributeSyntax.OBJECT_NAME_SYNTAX)
                .references(ObjectType.MNTNER)
                .listValue());

        mapHelperAdd(new AttributeTypeBuilderImpl("mnt-nfy", "mn",  Enum.MNT_NFY)
                .doc("Specifies the e-mail address to be notified when an object protected by a mntner is successfully updated.")
                .syntax(AttributeSyntax.EMAIL_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("mnt-ref", "mz", Enum.MNT_REF)
                .doc("Specifies the maintainer objects that are entitled to add references " +
                        "to the organisation object from other objects.")
                .syntax(AttributeSyntax.OBJECT_NAME_SYNTAX)
                .references(ObjectType.MNTNER)
                .listValue());

        mapHelperAdd(new AttributeTypeBuilderImpl("mnt-routes", "mu", Enum.MNT_ROUTES)
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

        mapHelperAdd(new AttributeTypeBuilderImpl("mp-default", "ma", Enum.MP_DEFAULT)
                .doc("Specifies default multiprotocol routing policies.")
                .syntax(AttributeSyntax.MP_DEFAULT_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("mp-export", "me", Enum.MP_EXPORT)
                .doc("Specifies a multiprotocol export policy expression.")
                .syntax(AttributeSyntax.MP_EXPORT_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("mp-filter", "mf", Enum.MP_FILTER)
                .doc("Defines the set's multiprotocol policy filter.")
                .syntax(AttributeSyntax.MP_FILTER_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("mp-import", "my", Enum.MP_IMPORT)
                .doc("Specifies multiprotocol import policy expression.")
                .syntax(AttributeSyntax.MP_IMPORT_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("mp-members", "mm", Enum.MP_MEMBERS)
                .doc("Lists the multiprotocol members of the set.")
                .syntax(AttributeSyntax.MP_MEMBERS_SYNTAX).listValue());

        mapHelperAdd(new AttributeTypeBuilderImpl("mp-peer", "mp", Enum.MP_PEER)
                .doc(new Multiple(new HashMap<ObjectType, String>() {{
                    put(ObjectType.INET_RTR, "Details of any (interior or exterior) multiprotocol router peerings.");
                    put(ObjectType.PEERING_SET, "Defines a multiprotocol peering that can be used for importing or exporting routes.");
                }}))
                .syntax(AttributeSyntax.MP_PEER_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("mp-peering", "mg", Enum.MP_PEERING)
                .doc("Defines a multiprotocol peering that can be used for importing or exporting routes.")
                .syntax(AttributeSyntax.MP_PEERING_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("netname", "na", Enum.NETNAME)
                .doc("The name of a range of IP address space.")
                .syntax(AttributeSyntax.NETNAME_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("nic-hdl", "nh", Enum.NIC_HDL)
                .doc("Specifies the NIC handle of a role or person object. When creating an object, one can also " +
                        "specify an \"AUTO\" NIC handle by setting the value of the attribute to \"AUTO-1\" " +
                        "or AUTO-1<Initials>. In such case the database will assign the NIC handle automatically.")
                .syntax(AttributeSyntax.NIC_HANDLE_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("notify", "ny", Enum.NOTIFY)
                .doc("Specifies the e-mail address to which notifications of changes to an object should be sent. " +
                        "This attribute is filtered from the default whois output.")
                .syntax(AttributeSyntax.EMAIL_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("nserver", "ns", Enum.NSERVER)
                .doc("Specifies the nameservers of the domain.")
                .syntax(AttributeSyntax.NSERVER_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("org", "og", Enum.ORG)
                .doc("Points to an existing organisation object representing the entity that holds the resource.")
                .syntax(AttributeSyntax.ORGANISATION_SYNTAX)
                .references(ObjectType.ORGANISATION));

        mapHelperAdd(new AttributeTypeBuilderImpl("org-name", "on", Enum.ORG_NAME)
                .doc("Specifies the name of the organisation that this organisation object represents in the whois" +
                        "database. This is an ASCII-only text attribute. The restriction is because this attribute is" +
                        "a look-up key and the whois protocol does not allow specifying character sets in queries. " +
                        "The user can put the name of the organisation in non-ASCII character sets in " +
                        "the \"descr:\" attribute if required.")
                .syntax(AttributeSyntax.ORG_NAME_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("org-type", "ot", Enum.ORG_TYPE)
                .doc("Specifies the type of the organisation.")
                .syntax(AttributeSyntax.ORG_TYPE_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("organisation", "oa", Enum.ORGANISATION)
                .doc("Specifies the ID of an organisation object. When creating an object, one has to specify " +
                        "an \"AUTO\" ID by setting the value of the attribute to \"AUTO-1\" or \"AUTO-1<letterCombination>\", " +
                        "so the database will assign the ID automatically.")
                .syntax(AttributeSyntax.ORGANISATION_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("origin", "or", Enum.ORIGIN)
                .doc("Specifies the AS that originates the route." +
                        "The corresponding aut-num object should be registered in the database.")
                .syntax(AttributeSyntax.AS_NUMBER_SYNTAX)
                .references(ObjectType.AUT_NUM));

        mapHelperAdd(new AttributeTypeBuilderImpl("owner", "ow", Enum.OWNER)
                .doc("Specifies the owner of the public key.")
                .syntax(AttributeSyntax.GENERATED_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("peer", "pe", Enum.PEER)
                .doc("Details of any (interior or exterior) router peerings.")
                .syntax(AttributeSyntax.PEER_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("peering", "pg", Enum.PEERING)
                .doc("Defines a peering that can be used for importing or exporting routes.")
                .syntax(AttributeSyntax.PEERING_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("peering-set", "ps", Enum.PEERING_SET)
                .doc("Specifies the name of the peering-set.")
                .syntax(AttributeSyntax.PEERING_SET_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("person", "pn", Enum.PERSON)
                .doc("Specifies the full name of an administrative, technical or zone contact person for " +
                        "other objects in the database." +
                        "Person name cannot contain titles such as \"Dr.\", \"Prof.\", \"Mv.\", \"Ms.\", \"Mr.\", etc." +
                        "It is composed of alphabetic characters.")
                .syntax(AttributeSyntax.PERSON_ROLE_NAME_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("phone", "ph", Enum.PHONE)
                .doc("Specifies a telephone number of the contact.")
                .syntax(AttributeSyntax.PHONE_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("ping-hdl", "pc", Enum.PING_HDL)
                .doc("References a person or role capable of responding to queries concerning the IP address(es) " +
                        "specified in the 'pingable' attribute.")
                .syntax(AttributeSyntax.NIC_HANDLE_SYNTAX)
                .references(ObjectType.PERSON, ObjectType.ROLE));

        mapHelperAdd(new AttributeTypeBuilderImpl("pingable", "pa", Enum.PINGABLE)
                .doc("Allows a network operator to advertise an IP address of a node that should be reachable from outside " +
                        "networks. This node can be used as a destination address for diagnostic tests. " +
                        "The IP address must be within the address range of the prefix containing this attribute.")
                .syntax(AttributeSyntax.PINGABLE_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("poem", "po", Enum.POEM)
                .doc("Specifies the title of the poem.")
                .syntax(AttributeSyntax.POEM_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("poetic-form", "pf", Enum.POETIC_FORM)
                .doc("Specifies the poem type.")
                .syntax(AttributeSyntax.POETIC_FORM_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("referral-by", "rb", Enum.REFERRAL_BY)
                .doc("This attribute is required in the maintainer object. It may never be altered after the addition " +
                        "of the maintainer. This attribute refers to the maintainer that created this maintainer. " +
                        "It may be multiple if more than one signature appeared on the transaction creating the object.")
                .syntax(AttributeSyntax.OBJECT_NAME_SYNTAX)
                .references(ObjectType.MNTNER));

        mapHelperAdd(new AttributeTypeBuilderImpl("ref-nfy", "rn", Enum.REF_NFY)
                .doc("Specifies the e-mail address to be notified when a reference to the organisation object is added " +
                        "or removed. This attribute is filtered from the default whois output when at least one of the " +
                        "objects returned by the query contains an abuse-mailbox attribute.")
                .syntax(AttributeSyntax.EMAIL_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("remarks", "rm", Enum.REMARKS)
                .doc("Contains remarks.")
                .syntax(AttributeSyntax.FREE_FORM_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("role", "ro", Enum.ROLE)
                .doc("Specifies the full name of a role entity, e.g. APNIC DBM.")
                .syntax(AttributeSyntax.PERSON_ROLE_NAME_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("route", "rt", Enum.ROUTE)
                .doc("Specifies the prefix of the interAS route. Together with the \"origin:\" attribute, " +
                        "constitutes a primary key of the route object.")
                .syntax(AttributeSyntax.ROUTE_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("route6", "r6", Enum.ROUTE6)
                .doc("Specifies the IPv6 prefix of the interAS route. Together with the \"origin:\" attribute," +
                        "constitutes a primary key of the route6 object.")
                .syntax(AttributeSyntax.ROUTE6_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("route-set", "rs", Enum.ROUTE_SET)
                .doc("Specifies the name of the route set. It is a primary key for the route-set object.")
                .syntax(AttributeSyntax.ROUTE_SET_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("rtr-set", "is", Enum.RTR_SET)
                .doc("Defines the name of the rtr-set.")
                .syntax(AttributeSyntax.RTR_SET_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("signature", "sg", Enum.SIGNATURE)
                .doc("References a key-cert object representing a CSIRT public key used by the team to sign their correspondence.")
                .syntax(AttributeSyntax.KEY_CERT_SYNTAX)
                .references(ObjectType.KEY_CERT));

        mapHelperAdd(new AttributeTypeBuilderImpl("source", "so", Enum.SOURCE)
                .doc("Specifies the registry where the object is registered. Should be \"APNIC\" for the APNIC Database.")
                .syntax(AttributeSyntax.SOURCE_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("status", "st", Enum.STATUS)
                .doc("Specifies the status of the address range represented by inetnum or inet6num object.")
                .syntax(AttributeSyntax.STATUS_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("tech-c", "tc", Enum.TECH_C)
                .doc("References a technical contact.")
                .syntax(AttributeSyntax.NIC_HANDLE_SYNTAX)
                .references(ObjectType.PERSON, ObjectType.ROLE));

        mapHelperAdd(new AttributeTypeBuilderImpl("text", "tx", Enum.TEXT)
                .doc("Text of the poem. Must be humorous, but not malicious or insulting.")
                .syntax(AttributeSyntax.FREE_FORM_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("upd-to", "dt", Enum.UPD_TO)
                .doc("Specifies the e-mail address to be notified when an object protected by a mntner is unsuccessfully updated.")
                .syntax(AttributeSyntax.EMAIL_SYNTAX));

        mapHelperAdd(new AttributeTypeBuilderImpl("zone-c", "zc", Enum.ZONE_C)
                .doc("References a zone contact.")
                .syntax(AttributeSyntax.NIC_HANDLE_SYNTAX)
                .references(ObjectType.PERSON, ObjectType.ROLE));
    }

    private static void mapHelperAdd(AttributeTypeBuilderImpl entry) {
        localMap.put(entry.getEnumType(), entry);
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
        return name;
    }

    public String getFlag() {
        return flag;
    }

    public Documented getDescription() {
        return description;
    }

    public String getDescription(ObjectType objectType) {
        return objectType.getName();
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
}

