package net.ripe.db.whois.api.whois.rdap;

import com.google.common.collect.Lists;
import net.ripe.db.whois.api.whois.rdap.domain.Autnum;
import net.ripe.db.whois.api.whois.rdap.domain.Domain;
import net.ripe.db.whois.api.whois.rdap.domain.Entity;
import net.ripe.db.whois.api.whois.rdap.domain.Ip;
import net.ripe.db.whois.api.whois.rdap.domain.Nameserver;
import net.ripe.db.whois.common.rpsl.RpslObject;
import org.joda.time.LocalDateTime;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

import javax.xml.datatype.XMLGregorianCalendar;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.hasXPath;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertThat;

public class RdapObjectMapperTest {
    private static final Logger LOGGER = LoggerFactory.getLogger(RdapObjectMapperTest.class);

    private static String VERSION_DATETIME = "2044-04-26T00:02:03.000";
    private static final LocalDateTime VERSION_TIMESTAMP = LocalDateTime.parse(VERSION_DATETIME);
    private static final XMLGregorianCalendar XML_GC_VERSION_TIMESTAMP = RdapObjectMapper.dtf.newXMLGregorianCalendar(VERSION_DATETIME + "+10:00");

    private static final String REQUEST_URL =  "http://localhost";
    private static final String BASE_URL =  "http://localhost";

    @Test
    public void ip() {
        final Ip result = (Ip) map((RpslObject.parse("" +
                "inetnum:        10.0.0.0 - 10.255.255.255\n" +
                "netname:        RIPE-NCC\n" +
                "descr:          some descr\n" +
                "country:        NL\n" +
                "admin-c:        TP1-TEST\n" +
                "tech-c:         TP1-TEST\n" +
                "status:         OTHER\n" +
                "mnt-by:         TST-MNT\n" +
                "mnt-lower:      TST-MNT\n" +
                "mnt-domains:    TST-MNT\n" +
                "mnt-routes:     TST-MNT\n" +
                "mnt-irt:        irt-IRT1\n" +
                "notify:         notify@test.net\n" +
                "org:            ORG-TOL1-TEST\n" +
                "changed:        ripe@test.net 20120101\n" +
                "source:         TEST")));

        assertThat(result.getRdapConformance(), is(RdapObjectMapper.RDAP_CONFORMANCE_LEVEL));
        assertThat(result.getHandle(), is("10.0.0.0 - 10.255.255.255"));
        assertThat(result.getEvents(), hasSize(1));
        assertThat(result.getEvents().get(0).getEventAction(), is("last changed"));
        assertThat(result.getEvents().get(0).getEventDate(), is(XML_GC_VERSION_TIMESTAMP));
        assertThat(result.getCountry(), is("NL"));
        assertThat(result.getEndAddress(), is("10.255.255.255"));
        assertThat(result.getIpVersion(), is("v4"));
        assertThat(result.getName(), is("RIPE-NCC"));
        assertThat(result.getParentHandle(), is(nullValue()));
        assertThat(result.getStartAddress(), is("10.0.0.0"));
        assertThat(result.getType(), is("OTHER"));
        assertThat(result.getLinks(), hasSize(1));
        assertThat(result.getLinks().get(0).getRel(), is("self"));
// TODO: [RL] test for copyright in notices
//        assertThat(result.getLinks().get(1).getRel(), is("copyright"));
        assertThat(result.getRemarks(), hasSize(1));
        assertThat(result.getRemarks().get(0).getDescription().get(0), is("some descr"));
        assertThat(result.getEntities(), hasSize(2));
        assertThat(result.getEntities().get(0).getHandle(), is("irt-IRT1"));
        assertThat(result.getEntities().get(0).getRoles().size(), is(1));
        assertThat(result.getEntities().get(1).getHandle(), is("TP1-TEST"));
        assertThat(result.getEntities().get(1).getRoles().size(), is(2));
    }

    @Test
    public void autnum() {
        final Autnum result = (Autnum) map((RpslObject.parse("" +
                "aut-num:        AS102\n" +
                "as-name:        End-User-2\n" +
                "member-of:      AS-TESTSET\n" +
                "descr:          description\n" +
                "import:         from AS1 accept ANY\n" +
                "export:         to AS1 announce AS2\n" +
                "default:        to AS1\n" +
                "mp-import:      afi ipv6.unicast from AS1 accept ANY\n" +
                "mp-export:      afi ipv6.unicast to AS1 announce AS2\n" +
                "mp-default:     to AS1\n" +
                "remarks:        remarkable\n" +
                "org:            ORG-NCC1-RIPE\n" +
                "admin-c:        AP1-TEST\n" +
                "tech-c:         AP1-TEST\n" +
                "notify:         noreply@ripe.net\n" +
                "mnt-lower:      UPD-MNT\n" +
                "mnt-routes:     UPD-MNT\n" +
                "mnt-by:         UPD-MNT\n" +
                "changed:        noreply@ripe.net 20120101\n" +
                "source:         TEST\n" +
                "password:       update")));

        assertThat(result.getRdapConformance(), is(RdapObjectMapper.RDAP_CONFORMANCE_LEVEL));
        assertThat(result.getHandle(), is("AS102"));
        assertThat(result.getStartAutnum(), is(102l));
        assertThat(result.getEndAutnum(), is(102l));
        assertThat(result.getEvents(), hasSize(1));
        assertThat(result.getEvents().get(0).getEventAction(), is("last changed"));
        assertThat(result.getEvents().get(0).getEventDate(), is(XML_GC_VERSION_TIMESTAMP));
        assertThat(result.getName(), is("End-User-2"));
        assertThat(result.getType(), is("DIRECT ALLOCATION"));
        assertThat(result.getLinks(), hasSize(1));
        assertThat(result.getLinks().get(0).getRel(), is("self"));
        final String selfUrl = BASE_URL + "/" + Autnum.class.getSimpleName().toLowerCase() + "/102";
        assertThat(result.getLinks().get(0).getValue(), is(selfUrl));
        assertThat(result.getLinks().get(0).getHref(), is(selfUrl));
// TODO: [RL] test for copyright in notices
//        assertThat(result.getLinks().get(1).getRel(), is("copyright"));
        assertThat(result.getRemarks(), hasSize(2));
        assertThat(result.getRemarks().get(0).getDescription().get(0), is("description"));
        assertThat(result.getRemarks().get(1).getDescription().get(0), is("remarkable"));
        assertThat(result.getEntities(), hasSize(1));
        assertThat(result.getEntities().get(0).getHandle(), is("AP1-TEST"));
        assertThat(result.getEntities().get(0).getRoles().size(), is(2));

    }

    @Test
    public void domain() {
        final Domain result = (Domain) map((RpslObject.parse("" +
                "domain:          2.1.2.1.5.5.5.2.0.2.1.e164.arpa\n" +
                "descr:           enum domain\n" +
                "admin-c:         TEST-PN\n" +
                "tech-c:          TEST-PN\n" +
                "zone-c:          TEST-PN\n" +
                "nserver:         ns.1.net\n" +
                "mnt-by:          RIPE-NCC-MNT\n" +
                "changed:         test@ripe.net 20120505\n" +
                "source:          TEST\n" +
                "password:        update")));

        assertThat(result.getRdapConformance(), is(RdapObjectMapper.RDAP_CONFORMANCE_LEVEL));
        assertThat(result.getHandle(), is("2.1.2.1.5.5.5.2.0.2.1.e164.arpa"));
        assertThat(result.getLdhName(), is("2.1.2.1.5.5.5.2.0.2.1.e164.arpa"));
        assertThat(result.getNameServers(), hasSize(1));
        assertThat(result.getNameServers().get(0).getLdhName(), is("ns.1.net"));
        assertThat(result.getEvents(), hasSize(1));
        assertThat(result.getEvents().get(0).getEventAction(), is("last changed"));
        assertThat(result.getEvents().get(0).getEventDate(), is(XML_GC_VERSION_TIMESTAMP));
        assertThat(result.getEvents().get(0).getEventActor(), is(nullValue()));
        assertThat(result.getLinks(), hasSize(1));
        assertThat(result.getLinks().get(0).getRel(), is("self"));
        final String selfUrl = BASE_URL + "/" + Domain.class.getSimpleName().toLowerCase() + "/2.1.2.1.5.5.5.2.0.2.1.e164.arpa";
        assertThat(result.getLinks().get(0).getValue(), is(selfUrl));
        assertThat(result.getLinks().get(0).getHref(), is(selfUrl));
// TODO: [RL] test for copyright in notices
//        assertThat(result.getLinks().get(1).getRel(), is("copyright"));
        assertThat(result.getRemarks(), hasSize(1));
        assertThat(result.getRemarks().get(0).getDescription().get(0), is("enum domain"));
        assertThat(result.getEntities(), hasSize(1));
        assertThat(result.getEntities().get(0).getHandle(), is("TEST-PN"));
        assertThat(result.getEntities().get(0).getRoles().size(), is(3));
    }

    @Test
    public void domain_31_12_202_in_addr_arpa() {
        final Domain result = (Domain)map((RpslObject.parse("" +
                "domain:   31.12.202.in-addr.arpa\n" +
                "descr:    Test domain\n" +
                "admin-c:  TP1-TEST\n" +
                "tech-c:   TP1-TEST\n" +
                "zone-c:   TP1-TEST\n" +
                "notify:   notify@test.net.au\n" +
                "nserver:  ns1.test.com.au 10.0.0.1\n" +
                "nserver:  ns1.test.com.au 2001:10::1\n" +
                "nserver:  ns2.test.com.au 10.0.0.2\n" +
                "nserver:  ns2.test.com.au 2001:10::2\n" +
                "nserver:  ns3.test.com.au\n" +
                "ds-rdata: 52151 1 1 13ee60f7499a70e5aadaf05828e7fc59e8e70bc1\n" +
                "ds-rdata: 17881 5 1 2e58131e5fe28ec965a7b8e4efb52d0a028d7a78\n" +
                "ds-rdata: 17881 5 2 8c6265733a73e5588bfac516a4fcfbe1103a544b95f254cb67a21e474079547e\n" +
                "changed:  test@test.net.au 20010816\n" +
                "changed:  test@test.net.au 20121121\n" +
                "mnt-by:   OWNER-MNT\n" +
                "source:   TEST\n")));

        assertThat(result.getRdapConformance(), is(RdapObjectMapper.RDAP_CONFORMANCE_LEVEL));
        assertThat(result.getHandle(), is("31.12.202.in-addr.arpa"));
        assertThat(result.getLdhName(), is("31.12.202.in-addr.arpa"));

        assertThat(result.getNameServers(), hasSize(3));

        // For easy testing of unordered List<Object> values using xpath
        Document domResult = RdapHelperUtils.toDOM(result);
        LOGGER.info(RdapHelperUtils.DOMToString(domResult));
        String prefixpath = "/" + Domain.class.getName() + "/nameServers/" + Nameserver.class.getName();

        // Use xpath to test for presence of bean values in unordered list
        assertThat(domResult, hasXPath(prefixpath + "/ldhName[text() = 'ns1.test.com.au']"));
        assertThat(domResult, hasXPath(prefixpath + "/ldhName[text() = 'ns1.test.com.au']/../ipAddresses/ipv4/string[text() = '10.0.0.1/32']"));
        assertThat(domResult, hasXPath(prefixpath + "/ldhName[text() = 'ns1.test.com.au']/../ipAddresses/ipv6/string[text() = '2001:10::1/128']"));

        assertThat(domResult, hasXPath(prefixpath + "/ldhName[text() = 'ns2.test.com.au']"));
        assertThat(domResult, hasXPath(prefixpath + "/ldhName[text() = 'ns2.test.com.au']/../ipAddresses/ipv4/string[text() = '10.0.0.2/32']"));
        assertThat(domResult, hasXPath(prefixpath + "/ldhName[text() = 'ns2.test.com.au']/../ipAddresses/ipv6/string[text() = '2001:10::2/128']"));

        assertThat(domResult, hasXPath(prefixpath + "/ldhName[text() = 'ns3.test.com.au']"));


        assertThat(result.getEvents(), hasSize(1));
        assertThat(result.getEvents().get(0).getEventAction(), is("last changed"));
        assertThat(result.getEvents().get(0).getEventDate(), is(XML_GC_VERSION_TIMESTAMP));
        assertThat(result.getEvents().get(0).getEventActor(), is(nullValue()));
        assertThat(result.getLinks(), hasSize(1));
        assertThat(result.getLinks().get(0).getRel(), is("self"));
        final String selfUrl = BASE_URL + "/" + Domain.class.getSimpleName().toLowerCase() + "/31.12.202.in-addr.arpa";
        assertThat(result.getLinks().get(0).getValue(), is(selfUrl));
        assertThat(result.getLinks().get(0).getHref(), is(selfUrl));
// TODO: [RL] test for copyright in notices
//        assertThat(result.getLinks().get(1).getRel(), is("copyright"));
        assertThat(result.getRemarks(), hasSize(1));
        assertThat(result.getRemarks().get(0).getDescription().get(0), is("Test domain"));
        assertThat(result.getEntities(), hasSize(1));
        assertThat(result.getEntities().get(0).getHandle(), is("TP1-TEST"));
        assertThat(result.getEntities().get(0).getRoles().size(), is(3));
        assertThat(result.getSecureDNS().isDelegationSigned(), is(true));

        assertThat(result.getSecureDNS().getDsData(), hasSize(3));
        assertThat(result.getSecureDNS().getDsData().get(0).getKeyTag(), is(52151L));
        assertThat(result.getSecureDNS().getDsData().get(0).getAlgorithm(), is((short) 1));
        assertThat(result.getSecureDNS().getDsData().get(0).getDigest(), is("13ee60f7499a70e5aadaf05828e7fc59e8e70bc1"));
        assertThat(result.getSecureDNS().getDsData().get(0).getDigestType(), is(1L));

        assertThat(result.getSecureDNS().getDsData().get(1).getKeyTag(), is(17881L));
        assertThat(result.getSecureDNS().getDsData().get(1).getAlgorithm(), is((short)5));
        assertThat(result.getSecureDNS().getDsData().get(1).getDigest(), is("2e58131e5fe28ec965a7b8e4efb52d0a028d7a78"));
        assertThat(result.getSecureDNS().getDsData().get(1).getDigestType(), is(1L));

        assertThat(result.getSecureDNS().getDsData().get(2).getKeyTag(), is(17881L));
        assertThat(result.getSecureDNS().getDsData().get(2).getAlgorithm(), is((short)5));
        assertThat(result.getSecureDNS().getDsData().get(2).getDigest(), is("8c6265733a73e5588bfac516a4fcfbe1103a544b95f254cb67a21e474079547e"));
        assertThat(result.getSecureDNS().getDsData().get(2).getDigestType(), is(2L));

    }

    @Test
    public void domain_102_130_in_addr_arpa() {
        final Domain result = (Domain)map((RpslObject.parse("" +
                "domain:         102.130.in-addr.arpa\n" +
                "descr:          domain object for 130.102.0.0 - 130.102.255.255\n" +
                "country:        AU\n" +
                "admin-c:        HM53-AP\n" +
                "tech-c:         HM53-AP\n" +
                "zone-c:         HM53-AP\n" +
                "nserver:        NS1.UQ.EDU.AU\n" +
                "nserver:        NS2.UQ.EDU.AU\n" +
                "nserver:        NS3.UQ.EDU.AU\n" +
                "nserver:        ns4.uqconnect.net\n" +
                "notify:         hostmaster@uq.edu.au\n" +
                "mnt-by:         MAINT-AU-UQ\n" +
                "changed:        hm-changed@apnic.net 20031020\n" +
                "changed:        hm-changed@apnic.net 20040319\n" +
                "changed:        d.thomas@its.uq.edu.au 20070226\n" +
                "source:         APNIC\n")));

        assertThat(result.getRdapConformance(), is(RdapObjectMapper.RDAP_CONFORMANCE_LEVEL));
        assertThat(result.getHandle(), is("102.130.in-addr.arpa"));
        assertThat(result.getLdhName(), is("102.130.in-addr.arpa"));
        assertThat(result.getNameServers(), hasSize(4));

        // For easy testing of unordered List<Object> values using xpath
        Document domResult = RdapHelperUtils.toDOM(result);
        //LOGGER.info(RdapHelperUtils.DOMToString(domResult));
        String prefixpath = "/" + Domain.class.getName() + "/nameServers/" + Nameserver.class.getName();

        // Use xpath to test for presence of bean values in unordered list
        assertThat(domResult, hasXPath(prefixpath+ "/ldhName[text() = 'NS1.UQ.EDU.AU']"));
        assertThat(domResult, hasXPath(prefixpath + "/ldhName[text() = 'NS2.UQ.EDU.AU']"));
        assertThat(domResult, hasXPath(prefixpath + "/ldhName[text() = 'NS3.UQ.EDU.AU']"));
        assertThat(domResult, hasXPath(prefixpath + "/ldhName[text() = 'ns4.uqconnect.net']"));

        assertThat(result.getEntities(), hasSize(1));
        assertThat(result.getEntities().get(0).getHandle(), is("HM53-AP"));
        assertThat(result.getEntities().get(0).getRoles().size(), is(3));

        assertThat(result.getRemarks(), hasSize(1));
        assertThat(result.getRemarks().get(0).getDescription().get(0), is("domain object for 130.102.0.0 - 130.102.255.255"));
        assertThat(result.getLinks().get(0).getRel(), is("self"));
        final String selfUrl = BASE_URL + "/" + Domain.class.getSimpleName().toLowerCase() + "/102.130.in-addr.arpa";
        assertThat(result.getLinks().get(0).getValue(), is(selfUrl));
        assertThat(result.getLinks().get(0).getHref(), is(selfUrl));

        assertThat(result.getEvents().get(0).getEventAction(), is("last changed"));
        assertThat(result.getEvents().get(0).getEventDate(), is(XML_GC_VERSION_TIMESTAMP));
        assertThat(result.getEvents().get(0).getEventActor(), is(nullValue()));
    }

    @Test
    public void domain_29_12_202_in_addr_arpa() {
        final Domain result = (Domain)map((RpslObject.parse("" +
                "domain:         29.12.202.in-addr.arpa\n" +
                "descr:          zone for 202.12.29.0/24\n" +
                "admin-c:        NO4-AP\n" +
                "tech-c:         AIC1-AP\n" +
                "zone-c:         NO4-AP\n" +
                "nserver:        cumin.apnic.net\n" +
                "nserver:        tinnie.apnic.net\n" +
                "nserver:        tinnie.arin.net\n" +
                "ds-rdata:       55264 5 1 ( 8bb4b233cbcf8593c6f153fccd4d805179b972a4 )\n" +
                "ds-rdata:       55264 5 2 ( b44b18643775f9fdc76ee312667c2b350c1e02f3e43f8027f2c55777a429095a )\n" +
                "mnt-by:         MAINT-APNIC-IS-AP\n" +
                "changed:        hm-changed@apnic.net 20120504\n" +
                "changed:        hm-changed@apnic.net 20120508\n" +
                "source:         APNIC\n")));

        assertThat(result.getRdapConformance(), is(RdapObjectMapper.RDAP_CONFORMANCE_LEVEL));
        assertThat(result.getHandle(), is("29.12.202.in-addr.arpa"));
        assertThat(result.getLdhName(), is("29.12.202.in-addr.arpa"));

        assertThat(result.getNameServers(), hasSize(3));

        // For easy testing of unordered List<Object> values using xpath
        Document domResult = RdapHelperUtils.toDOM(result);
        //LOGGER.info(RdapHelperUtils.DOMToString(domResult));
        String prefixpath = "/" + Domain.class.getName() + "/nameServers/" + Nameserver.class.getName();

        // Use xpath to test for presence of bean values in unordered list
        assertThat(domResult, hasXPath(prefixpath + "/ldhName[text() = 'cumin.apnic.net']"));
        assertThat(domResult, hasXPath(prefixpath + "/ldhName[text() = 'tinnie.apnic.net']"));
        assertThat(domResult, hasXPath(prefixpath + "/ldhName[text() = 'tinnie.arin.net']"));

        assertThat(result.getSecureDNS().isDelegationSigned(), is(true));
        assertThat(result.getSecureDNS().getDsData(), hasSize(2));
        assertThat(result.getSecureDNS().getDsData().get(0).getKeyTag(), is(55264L));
        assertThat(result.getSecureDNS().getDsData().get(0).getAlgorithm(), is((short) 5));
        assertThat(result.getSecureDNS().getDsData().get(0).getDigest(), is("8bb4b233cbcf8593c6f153fccd4d805179b972a4"));
        assertThat(result.getSecureDNS().getDsData().get(0).getDigestType(), is(1L));

        assertThat(result.getSecureDNS().getDsData().get(1).getKeyTag(), is(55264L));
        assertThat(result.getSecureDNS().getDsData().get(1).getAlgorithm(), is((short)5));
        assertThat(result.getSecureDNS().getDsData().get(1).getDigest(), is("b44b18643775f9fdc76ee312667c2b350c1e02f3e43f8027f2c55777a429095a"));
        assertThat(result.getSecureDNS().getDsData().get(1).getDigestType(), is(2L));

        assertThat(result.getEntities(), hasSize(2));
        assertThat(result.getEntities().get(0).getHandle(), is("AIC1-AP"));
        assertThat(result.getEntities().get(0).getRoles().size(), is(1));

        assertThat(result.getEntities().get(1).getHandle(), is("NO4-AP"));
        assertThat(result.getEntities().get(1).getRoles(), containsInAnyOrder("administrative", "zone"));

        assertThat(result.getRemarks(), hasSize(1));
        assertThat(result.getRemarks().get(0).getTitle(), is("description"));
        assertThat(result.getRemarks().get(0).getDescription().get(0), is("zone for 202.12.29.0/24"));

        assertThat(result.getLinks(), hasSize(1));
        assertThat(result.getLinks().get(0).getRel(), is("self"));
        final String selfUrl = BASE_URL + "/" + Domain.class.getSimpleName().toLowerCase() + "/29.12.202.in-addr.arpa";
        assertThat(result.getLinks().get(0).getValue(), is(selfUrl));
        assertThat(result.getLinks().get(0).getHref(), is(selfUrl));

        assertThat(result.getEvents(), hasSize(1));
        assertThat(result.getEvents().get(0).getEventAction(), is("last changed"));
        assertThat(result.getEvents().get(0).getEventDate(), is(XML_GC_VERSION_TIMESTAMP));
        assertThat(result.getEvents().get(0).getEventActor(), is(nullValue()));
    }

    @Test
    public void person() {
        final Entity result = (Entity) map(RpslObject.parse("" +
                "person:        First Last\n" +
                "address:       Singel 258\n" +
                "phone:         +31 20 123456\n" +
                "fax-no:        +31 20 123457\n" +
                "e-mail:        first@last.org\n" +
                "org:           ORG-TOL1-TEST\n" +
                "nic-hdl:       FL1-TEST\n" +
                "remarks:       remark\n" +
                "notify:        first@last.org\n" +
                "abuse-mailbox: first@last.org\n" +
                "mnt-by:        TST-MNT\n" +
                "changed:       first@last.org 20120220\n" +
                "source:        TEST"));

        assertThat(result.getRdapConformance(), is(RdapObjectMapper.RDAP_CONFORMANCE_LEVEL));
        assertThat(result.getHandle(), is("FL1-TEST"));
        assertThat(result.getRemarks(), hasSize(1));
        assertThat(result.getRemarks().get(0).getDescription().get(0), is("remark"));
        assertThat(result.getRemarks().get(0).getTitle(), is("remarks"));
        assertThat(result.getLinks(), hasSize(1));
        assertThat(result.getLinks().get(0).getRel(), is("self"));
        final String selfUrl = BASE_URL + "/" + Entity.class.getSimpleName().toLowerCase() + "/FL1-TEST";
        assertThat(result.getLinks().get(0).getValue(), is(selfUrl));
        assertThat(result.getLinks().get(0).getHref(), is(selfUrl));
        assertThat(result.getEvents(), hasSize(1));
        assertThat(result.getEvents().get(0).getEventAction(), is("last changed"));
        assertThat(result.getEvents().get(0).getEventDate(), is(XML_GC_VERSION_TIMESTAMP));
        assertThat(result.getEvents().get(0).getEventActor(), is(nullValue()));
    }

    @Test
    public void multiple_remarks() {
        final Entity result = (Entity) map(RpslObject.parse("" +
                "person:        First Last\n" +
                "descr:         descr1\n" +
                "descr:         descr2\n" +
                "descr:         descr2\n" +
                "descr:         descr1\n" +
                "address:       Singel 258\n" +
                "phone:         +31 20 123456\n" +
                "nic-hdl:       FL1-TEST\n" +
                "remarks:       remark1\n" +
                "remarks:       remark2\n" +
                "remarks:       remark2\n" +
                "remarks:       remark1\n" +
                "mnt-by:        TST-MNT\n" +
                "changed:       first@last.org 20120220\n" +
                "source:        TEST"));

        assertThat(result.getRdapConformance(), is(RdapObjectMapper.RDAP_CONFORMANCE_LEVEL));
        assertThat(result.getHandle(), is("FL1-TEST"));
        assertThat(result.getRemarks(), hasSize(2));
        assertThat(result.getRemarks().get(0).getTitle(), is("description"));
        assertThat(result.getRemarks().get(0).getDescription().get(0), is("descr1"));
        assertThat(result.getRemarks().get(0).getDescription().get(1), is("descr2"));
        assertThat(result.getRemarks().get(0).getDescription().get(2), is("descr2"));
        assertThat(result.getRemarks().get(0).getDescription().get(3), is("descr1"));
        assertThat(result.getRemarks().get(1).getTitle(), is("remarks"));
        assertThat(result.getRemarks().get(1).getDescription().get(0), is("remark1"));
        assertThat(result.getRemarks().get(1).getDescription().get(1), is("remark2"));
        assertThat(result.getRemarks().get(1).getDescription().get(2), is("remark2"));
        assertThat(result.getRemarks().get(1).getDescription().get(3), is("remark1"));
    }

    private Object map(final RpslObject rpslObject) {
        return RdapObjectMapper.map(REQUEST_URL,BASE_URL, rpslObject, Lists.<RpslObject>newArrayList(), VERSION_TIMESTAMP, Lists.<RpslObject>newArrayList(), null);
    }
}
