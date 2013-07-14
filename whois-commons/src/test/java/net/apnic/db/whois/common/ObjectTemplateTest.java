package net.apnic.db.whois.common;

import net.ripe.db.whois.common.rpsl.ObjectTemplate;
import net.ripe.db.whois.common.rpsl.ObjectType;
import org.junit.Test;

import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertThat;

public class ObjectTemplateTest {
    @Test
    public void verboseStringTemplateOrganisation() {
        final String template = ObjectTemplate.getTemplate(ObjectType.ORGANISATION).toVerboseString();

        assertThat(template, containsString("" +
                "organisation\n" +
                "\n" +
                "   Specifies the ID of an organisation object. When creating an object,\n" +
                "   one has to specify an \"AUTO\" ID by setting the value of the attribute\n" +
                "   to \"AUTO-1\" or \"AUTO-1<letterCombination>\", so the database will\n" +
                "   assign the ID automatically.\n" +
                "\n" +
                "     \n" +
                "\n" +
                "org-name\n" +
                "\n" +
                "   Specifies the name of the organisation that this organisation object\n" +
                "   represents in the whoisdatabase. This is an ASCII-only text attribute.\n" +
                "   The restriction is because this attribute isa look-up key and the\n" +
                "   whois protocol does not allow specifying character sets in queries.\n" +
                "   The user can put the name of the organisation in non-ASCII character\n" +
                "   sets in the \"descr:\" attribute if required.\n" +
                "\n" +
                "     \n" +
                "\n" +
                "org-type\n" +
                "\n" +
                "   Specifies the type of the organisation.\n" +
                "\n" +
                "     \n" +
                "\n" +
                "descr\n" +
                "\n" +
                "   A short decription related to the object.\n" +
                "\n" +
                "     A sequence of ASCII characters.\n" +
                "\n" +
                "remarks\n" +
                "\n" +
                "   Information about the object that cannot be stated in other\n" +
                "   attributes.\n" +
                "\n" +
                "     A sequence of ASCII characters.\n" +
                "\n" +
                "address\n" +
                "\n" +
                "   Full postal address of a contact\n" +
                "\n" +
                "     A sequence of ASCII characters.\n" +
                "\n" +
                "phone\n" +
                "\n" +
                "   A contact telephone number.\n" +
                "\n" +
                "     Contact telephone number. Can take one of the forms:\n" +
                "     \n" +
                "     +  <country code> <phone number> OR\n" +
                "     +  <country code> <area code> <phone number> OR\n" +
                "     +  <country code> <area code> <phone number> ext. <number>\n" +
                "\n" +
                "fax-no\n" +
                "\n" +
                "   A contact fax number.\n" +
                "\n" +
                "     Contact telephone number. Can take one of the forms:\n" +
                "     \n" +
                "     +  <country code> <phone number> OR\n" +
                "     +  <country code> <area code> <phone number> OR\n" +
                "     +  <country code> <area code> <phone number> ext. <number>\n" +
                "\n" +
                "e-mail\n" +
                "\n" +
                "   A contact e-mail address. This attribute is filtered from the default\n" +
                "   whois output when at least one of the objects returned by the query\n" +
                "   contains an abuse-mailbox attribute.\n" +
                "\n" +
                "     An e-mail address as defined in RFC 2822.\n" +
                "\n" +
                "geoloc\n" +
                "\n" +
                "   The location coordinates for the resource.\n" +
                "\n" +
                "     \n" +
                "\n" +
                "language\n" +
                "\n" +
                "   Identifies the language.\n" +
                "\n" +
                "     \n" +
                "\n" +
                "org\n" +
                "\n" +
                "   Points to an existing organisation object representing the entity that\n" +
                "   holds the resource.\n" +
                "\n" +
                "     \n" +
                "\n" +
                "admin-c\n" +
                "\n" +
                "   The NIC-handle of an on-site administrative contact.\n" +
                "\n" +
                "     From 2 to 4 characters optionally followed by up to 5 digits with \n" +
                "     the suffix \"-AP\"\n" +
                "\n" +
                "tech-c\n" +
                "\n" +
                "   The NIC-handle of a technical contact.\n" +
                "\n" +
                "     From 2 to 4 characters optionally followed by up to 5 digits with \n" +
                "     the suffix \"-AP\"\n" +
                "\n" +
                "abuse-c\n" +
                "\n" +
                "   References an abuse contact. This can only be a ROLE object containing\n" +
                "   an \"abuse-mailbox:\" attribute. Making this reference will remove any\n" +
                "   query limits for the ROLE object. These ROLE objects are considered to\n" +
                "   include only commercial data.\n" +
                "\n" +
                "     From 2 to 4 characters optionally followed by up to 5 digits with \n" +
                "     the suffix \"-AP\"\n" +
                "\n" +
                "ref-nfy\n" +
                "\n" +
                "   Specifies the e-mail address to be notified when a reference to the\n" +
                "   organisation object is added or removed. This attribute is filtered\n" +
                "   from the default whois output when at least one of the objects\n" +
                "   returned by the query contains an abuse-mailbox attribute.\n" +
                "\n" +
                "     An e-mail address as defined in RFC 2822.\n" +
                "\n" +
                "mnt-ref\n" +
                "\n" +
                "   Specifies the maintainer objects that are entitled to add references\n" +
                "   to the organisation object from other objects.\n" +
                "\n" +
                "     Made up of letters, digits, the character underscore \"_\",\n" +
                "     and the character hyphen \"-\"; the first character of a name\n" +
                "     must be a letter, and the last character of a name must be a\n" +
                "     letter or a digit.  The following words are reserved by\n" +
                "     RPSL, and they can not be used as names:\n" +
                "     \n" +
                "     any or to refine\n" +
                "     as-any not action networks\n" +
                "     rs-any atomic accept into\n" +
                "     peeras from announce inbound\n" +
                "     and at except outbound\n" +
                "     \n" +
                "     Names starting with certain prefixes are reserved for\n" +
                "     certain object types. Reserved prefixes are:\n" +
                "     \n" +
                "     AS-     reserved for as-set names\n" +
                "     RS-     reserved for route-set names\n" +
                "     RTRS-   reserved for rtr-set names\n" +
                "     FLTR-   reserved for filter-set names\n" +
                "     PRNG-   reserved for peering-set names\n" +
                "     IRT-    reserved for irt names (irt not yet implemented by APNIC)\n" +
                "\n" +
                "notify\n" +
                "\n" +
                "   Specifies the e-mail address to which notifications of changes to this\n" +
                "   object should be sent. This attribute is filtered from the default\n" +
                "   whois output.\n" +
                "\n" +
                "     An e-mail address as defined in RFC 2822.\n" +
                "\n" +
                "abuse-mailbox\n" +
                "\n" +
                "   Specifies the e-mail address to which abuse complaints should be sent.\n" +
                "   This attribute should only be used in the ROLE object. It will be\n" +
                "   deprecated from any other object. Adding this attribute to a ROLE\n" +
                "   object, then referencing it in an \"abuse-c:\" attribute of an\n" +
                "   ORGANISATION object, will remove any query limits for the ROLE object.\n" +
                "   These ROLE objects are considered to include only commercial data.\n" +
                "\n" +
                "     An e-mail address as defined in RFC 2822.\n" +
                "\n" +
                "mnt-by\n" +
                "\n" +
                "   Lists a registered mntner used to authorise and authenticate changes\n" +
                "   to this object.\n" +
                "\n" +
                "     Made up of letters, digits, the character underscore \"_\",\n" +
                "     and the character hyphen \"-\"; the first character of a name\n" +
                "     must be a letter, and the last character of a name must be a\n" +
                "     letter or a digit.  The following words are reserved by\n" +
                "     RPSL, and they can not be used as names:\n" +
                "     \n" +
                "     any or to refine\n" +
                "     as-any not action networks\n" +
                "     rs-any atomic accept into\n" +
                "     peeras from announce inbound\n" +
                "     and at except outbound\n" +
                "     \n" +
                "     Names starting with certain prefixes are reserved for\n" +
                "     certain object types. Reserved prefixes are:\n" +
                "     \n" +
                "     AS-     reserved for as-set names\n" +
                "     RS-     reserved for route-set names\n" +
                "     RTRS-   reserved for rtr-set names\n" +
                "     FLTR-   reserved for filter-set names\n" +
                "     PRNG-   reserved for peering-set names\n" +
                "     IRT-    reserved for irt names (irt not yet implemented by APNIC)\n" +
                "\n" +
                "changed\n" +
                "\n" +
                "   The email address of who last updated the object and the date it\n" +
                "   occurred. This attribute is filtered from the default whois output.\n" +
                "\n" +
                "     An e-mail address as defined in RFC 2822, followed by a date\n" +
                "     in the format YYYYMMDD.\n" +
                "\n" +
                "source\n" +
                "\n" +
                "   The database where the object is registered."));
    }

}
