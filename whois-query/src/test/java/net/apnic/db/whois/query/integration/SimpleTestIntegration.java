package net.apnic.db.whois.query.integration;

import com.google.common.collect.Lists;
import net.apnic.db.whois.common.IntegrationTest;
import net.ripe.db.whois.common.DateTimeProvider;
import net.ripe.db.whois.common.iptree.IpTreeUpdater;
import net.ripe.db.whois.common.rpsl.RpslObject;
import net.ripe.db.whois.common.support.DummyWhoisClient;
import net.ripe.db.whois.query.QueryServer;
import net.ripe.db.whois.query.support.AbstractWhoisIntegrationTest;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.springframework.beans.factory.annotation.Autowired;

import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertThat;

@Category(IntegrationTest.class)
public class SimpleTestIntegration extends AbstractWhoisIntegrationTest {

    @Autowired IpTreeUpdater ipTreeUpdater;
    @Autowired DateTimeProvider dateTimeProvider;

    @Before
    public void startupWhoisServer() {
        final RpslObject person = RpslObject.parse("person: ADM-TEST\naddress: address\nphone: +61738583100\nmnt-by:APNIC-HM-MNT\nadmin-c: ADM-TEST\nchanged: dbtest@apnic.net 20120707\nnic-hdl: ADM-TEST");
        final RpslObject mntner = RpslObject.parse("mntner: APNIC-HM-MNT\nmnt-by: APNIC-HM-MNT\ndescr: description\nadmin-c: ADM-TEST");
        databaseHelper.addObjects(Lists.newArrayList(person, mntner));

        databaseHelper.addObject("inetnum: 81.0.0.0 - 82.255.255.255\nnetname: NE\nmnt-by:APNIC-HM-MNT");
        databaseHelper.addObject("domain: 117.80.81.in-addr.arpa");
        databaseHelper.addObject("inetnum: 81.80.117.237 - 81.80.117.237\nnetname: NN\nstatus: OTHER");
        ipTreeUpdater.rebuild();
        queryServer.start();
    }

    @After
    public void shutdownWhoisServer() {
        queryServer.stop();
    }

    @Test
    public void verbose_description() {
        final String response = DummyWhoisClient.query(QueryServer.port, "-v inetnum");
        assertThat(response.replaceAll("[\r]",""), containsString("" +
                "The content of the attributes of the inetnum class are defined below:\n" +
                "\n" +
                "inetnum\n" +
                "\n" +
                "   Specifies a range of IPv4 that inetnum object presents. The ending\n" +
                "   address should be greater than the starting one.\n" +
                "\n" +
                "     <ipv4-address> - <ipv4-address>\n" +
                "\n" +
                "netname\n" +
                "\n" +
                "   The name of a range of IP address space.\n" +
                "\n" +
                "     Made up of letters, digits, the character underscore \"_\",\n" +
                "     and the character hyphen \"-\"; the first character of a name\n" +
                "     must be a letter, and the last character of a name must be a\n" +
                "     letter or a digit.\n" +
                "\n" +
                "descr\n" +
                "\n" +
                "   A short decription related to the object.\n" +
                "\n" +
                "     A sequence of ASCII characters.\n" +
                "\n" +
                "country\n" +
                "\n" +
                "   Identifies the country.\n" +
                "\n" +
                "     Valid two-letter ISO 3166 country code.\n" +
                "\n" +
                "geoloc\n" +
                "\n" +
                "   The location coordinates for the resource.\n" +
                "\n" +
                "     Location coordinates of the resource. Can take one of the following forms:\n" +
                "     \n" +
                "     [-90,90][-180,180]\n" +
                "\n" +
                "language\n" +
                "\n" +
                "   Identifies the language.\n" +
                "\n" +
                "     Valid two-letter ISO 639-1 language code.\n" +
                "\n" +
                "org\n" +
                "\n" +
                "   Points to an existing organisation object representing the entity that\n" +
                "   holds the resource.\n" +
                "\n" +
                "     The 'ORG-' string followed by 2 to 4 characters, followed by up to 5 digits\n" +
                "     followed by a source specification.  The first digit must not be \"0\".\n" +
                "     Source specification starts with \"-\" followed by source name up to\n" +
                "     9-character length.\n" +
                "\n" +
                "admin-c\n" +
                "\n" +
                "   References an on-site administrative contact.\n" +
                "\n" +
                "     From 2 to 4 characters optionally followed by up to 6 digits\n" +
                "     optionally followed by a source specification.  The first digit\n" +
                "     must not be \"0\".  Source specification starts with \"-\" followed\n" +
                "     by source name up to 9-character length.\n" +
                "\n" +
                "tech-c\n" +
                "\n" +
                "   References a technical contact.\n" +
                "\n" +
                "     From 2 to 4 characters optionally followed by up to 6 digits\n" +
                "     optionally followed by a source specification.  The first digit\n" +
                "     must not be \"0\".  Source specification starts with \"-\" followed\n" +
                "     by source name up to 9-character length.\n" +
                "\n" +
                "status\n" +
                "\n" +
                "   Specifies the status of the address range represented by inetnum or\n" +
                "   inet6num object.\n" +
                "\n" +
                "     Status can have one of these values:\n" +
                "     \n" +
                "     o ALLOCATED PA\n" +
                "     o ALLOCATED PI\n" +
                "     o ALLOCATED UNSPECIFIED\n" +
                "     o LIR-PARTITIONED PA\n" +
                "     o LIR-PARTITIONED PI\n" +
                "     o SUB-ALLOCATED PA\n" +
                "     o ASSIGNED PA\n" +
                "     o ASSIGNED PI\n" +
                "     o ASSIGNED ANYCAST\n" +
                "     o EARLY-REGISTRATION\n" +
                "     o NOT-SET\n" +
                "\n" +
                "remarks\n" +
                "\n" +
                "   Contains remarks.\n" +
                "\n" +
                "     A sequence of ASCII characters.\n" +
                "\n" +
                "notify\n" +
                "\n" +
                "   Specifies the e-mail address to which notifications of changes to an\n" +
                "   object should be sent. This attribute is filtered from the default\n" +
                "   whois output.\n" +
                "\n" +
                "     An e-mail address as defined in RFC 2822.\n" +
                "\n" +
                "mnt-by\n" +
                "\n" +
                "   Specifies the identifier of a registered mntner object used for\n" +
                "   authorisation of operations performed with the object that contains\n" +
                "   this attribute.\n" +
                "\n" +
                "     Made up of letters, digits, the character underscore \"_\",\n" +
                "     and the character hyphen \"-\"; the first character of a name\n" +
                "     must be a letter, and the last character of a name must be a\n" +
                "     letter or a digit.  The following words are reserved by\n" +
                "     RPSL, and they can not be used as names:\n" +
                "     \n" +
                "      any as-any rs-any peeras and or not atomic from to at\n" +
                "      action accept announce except refine networks into inbound\n" +
                "      outbound\n" +
                "     \n" +
                "     Names starting with certain prefixes are reserved for\n" +
                "     certain object types.  Names starting with \"as-\" are\n" +
                "     reserved for as set names.  Names starting with \"rs-\" are\n" +
                "     reserved for route set names.  Names starting with \"rtrs-\"\n" +
                "     are reserved for router set names. Names starting with\n" +
                "     \"fltr-\" are reserved for filter set names. Names starting\n" +
                "     with \"prng-\" are reserved for peering set names. Names\n" +
                "     starting with \"irt-\" are reserved for irt names.\n" +
                "\n" +
                "mnt-lower\n" +
                "\n" +
                "   Specifies the identifier of a registered mntner object used for\n" +
                "   hierarchical authorisation. Protects creation of objects directly (one\n" +
                "   level) below in the hierarchy of an object type. The authentication\n" +
                "   method of this maintainer object will then be used upon creation of\n" +
                "   any object directly below the object that contains the \"mnt-lower:\"\n" +
                "   attribute.\n" +
                "\n" +
                "     Made up of letters, digits, the character underscore \"_\",\n" +
                "     and the character hyphen \"-\"; the first character of a name\n" +
                "     must be a letter, and the last character of a name must be a\n" +
                "     letter or a digit.  The following words are reserved by\n" +
                "     RPSL, and they can not be used as names:\n" +
                "     \n" +
                "      any as-any rs-any peeras and or not atomic from to at\n" +
                "      action accept announce except refine networks into inbound\n" +
                "      outbound\n" +
                "     \n" +
                "     Names starting with certain prefixes are reserved for\n" +
                "     certain object types.  Names starting with \"as-\" are\n" +
                "     reserved for as set names.  Names starting with \"rs-\" are\n" +
                "     reserved for route set names.  Names starting with \"rtrs-\"\n" +
                "     are reserved for router set names. Names starting with\n" +
                "     \"fltr-\" are reserved for filter set names. Names starting\n" +
                "     with \"prng-\" are reserved for peering set names. Names\n" +
                "     starting with \"irt-\" are reserved for irt names.\n" +
                "\n" +
                "mnt-domains\n" +
                "\n" +
                "   Specifies the identifier of a registered mntner object used for\n" +
                "   reverse domain authorisation. Protects domain objects. The\n" +
                "   authentication method of this maintainer object will be used for any\n" +
                "   encompassing reverse domain object.\n" +
                "\n" +
                "     Made up of letters, digits, the character underscore \"_\",\n" +
                "     and the character hyphen \"-\"; the first character of a name\n" +
                "     must be a letter, and the last character of a name must be a\n" +
                "     letter or a digit.  The following words are reserved by\n" +
                "     RPSL, and they can not be used as names:\n" +
                "     \n" +
                "      any as-any rs-any peeras and or not atomic from to at\n" +
                "      action accept announce except refine networks into inbound\n" +
                "      outbound\n" +
                "     \n" +
                "     Names starting with certain prefixes are reserved for\n" +
                "     certain object types.  Names starting with \"as-\" are\n" +
                "     reserved for as set names.  Names starting with \"rs-\" are\n" +
                "     reserved for route set names.  Names starting with \"rtrs-\"\n" +
                "     are reserved for router set names. Names starting with\n" +
                "     \"fltr-\" are reserved for filter set names. Names starting\n" +
                "     with \"prng-\" are reserved for peering set names. Names\n" +
                "     starting with \"irt-\" are reserved for irt names.\n" +
                "\n" +
                "mnt-routes\n" +
                "\n" +
                "   This attribute references a maintainer object which is used in\n" +
                "   determining authorisation for the creation of route objects.\n" +
                "   After the reference to the maintainer, an optional list of\n" +
                "   prefix ranges inside of curly braces or the keyword \"ANY\" may\n" +
                "   follow. The default, when no additional set items are\n" +
                "   specified, is \"ANY\" or all more specifics. Please refer to\n" +
                "   RFC-2622 for more information.\n" +
                "\n" +
                "     <mnt-name> [ { list of <address-prefix-range> } | ANY ]\n" +
                "\n" +
                "mnt-irt\n" +
                "\n" +
                "   May appear in an inetnum or inet6num object. It points to an irt\n" +
                "   object representing a Computer Security Incident Response Team (CSIRT)\n" +
                "   that handles security incidents for the address space specified by the\n" +
                "   inetnum or inet6num object.\n" +
                "\n" +
                "     An irt name is made up of letters, digits, the character\n" +
                "     underscore \"_\", and the character hyphen \"-\"; it must start\n" +
                "     with \"irt-\", and the last character of a name must be a\n" +
                "     letter or a digit.\n" +
                "\n" +
                "changed\n" +
                "\n" +
                "   Specifies who submitted the update, and when the object was updated.\n" +
                "   This attribute is filtered from the default whois output.\n" +
                "\n" +
                "     An e-mail address as defined in RFC 2822, followed by a date\n" +
                "     in the format YYYYMMDD.\n" +
                "\n" +
                "source\n" +
                "\n" +
                "   Specifies the registry where the object is registered. Should be\n" +
                "   \"APNIC\" for the APNIC Database.\n" +
                "\n" +
                "     Made up of letters, digits, the character underscore \"_\",\n" +
                "     and the character hyphen \"-\"; the first character of a\n" +
                "     registry name must be a letter, and the last character of a\n" +
                "     registry name must be a letter or a digit.\n"));

    }
}
