package net.ripe.db.whois.api.whois.rdap;

import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.api.client.UniformInterfaceException;
import com.sun.jersey.api.client.WebResource;
import com.sun.jersey.api.client.config.ClientConfig;
import com.sun.jersey.api.client.config.DefaultClientConfig;
import net.ripe.db.whois.api.freetext.FreeTextIndex;
import net.ripe.db.whois.api.AbstractRestClientTest;
import net.ripe.db.whois.api.httpserver.Audience;
import net.ripe.db.whois.api.whois.rdap.domain.Autnum;
import net.ripe.db.whois.api.whois.rdap.domain.Domain;
import net.ripe.db.whois.api.whois.rdap.domain.Entity;
import net.ripe.db.whois.api.whois.rdap.domain.Event;
import net.ripe.db.whois.api.whois.rdap.domain.Ip;
import net.ripe.db.whois.api.whois.rdap.domain.Nameserver;
import net.ripe.db.whois.api.whois.rdap.domain.Link;
import net.ripe.db.whois.api.whois.rdap.domain.Notice;
import net.ripe.db.whois.api.whois.rdap.domain.Remark;
import net.ripe.db.whois.api.whois.rdap.domain.Role;
import net.ripe.db.whois.common.IntegrationTest;
import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HeaderElement;
import org.apache.commons.lang.StringUtils;
import org.joda.time.LocalDateTime;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.xml.datatype.XMLGregorianCalendar;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.hasXPath;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.lessThanOrEqualTo;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import org.springframework.beans.factory.annotation.Autowired;

@Category(IntegrationTest.class)
public class WhoisRdapServiceTestIntegration extends AbstractRestClientTest {
    private static final Logger LOGGER = LoggerFactory.getLogger(WhoisRdapServiceTestIntegration.class);
    private static final Audience AUDIENCE = Audience.PUBLIC;

    private static final String CONTENT_TYPE_HEADER = "Content-Type";
    @Autowired private FreeTextIndex freeTextIndex;

    @Before
    public void setup() throws Exception {
        freeTextIndex.rebuild();
        databaseHelper.addObject("" +
                "person: Test Person\n" +
                "nic-hdl: TP1-TEST");
        databaseHelper.addObject("" +
                "mntner:        OWNER-MNT\n" +
                "descr:         Owner Maintainer\n" +
                "admin-c:       TP1-TEST\n" +
                "upd-to:        noreply@ripe.net\n" +
                "auth:          MD5-PW $1$d9fKeTr2$Si7YudNf4rUGmR71n/cqk/ #test\n" +
                "mnt-by:        OWNER-MNT\n" +
                "referral-by:   OWNER-MNT\n" +
                "changed:       dbtest@ripe.net 20120101\n" +
                "source:        TEST");
        databaseHelper.updateObject("" +
                "person:        Test Person\n" +
                "address:       Singel 258\n" +
                "phone:         +31 6 12345678\n" +
                "nic-hdl:       TP1-TEST\n" +
                "mnt-by:        OWNER-MNT\n" +
                "changed:       dbtest@ripe.net 20120101\n" +
                "source:        TEST\n");
        databaseHelper.addObject("" +
                "person:        Test Person2\n" +
                "address:       Test Address\n" +
                "phone:         +61-1234-1234\n" +
                "e-mail:        noreply@ripe.net\n" +
                "mnt-by:        OWNER-MNT\n" +
                "nic-hdl:       TP2-TEST\n" +
                "changed:       noreply@ripe.net 20120101\n" +
                "source:        TEST\n");
        databaseHelper.addObject("" +
                "person:        Pauleth Palthen\n" +
                "address:       Singel 258\n" +
                "phone:         +31-1234567890\n" +
                "e-mail:        noreply@ripe.net\n" +
                "mnt-by:        OWNER-MNT\n" +
                "nic-hdl:       PP1-TEST\n" +
                "changed:       noreply@ripe.net 20120101\n" +
                "changed:       noreply@ripe.net 20120102\n" +
                "changed:       noreply@ripe.net 20120103\n" +
                "remarks:       remark\n" +
                "source:        TEST\n");
        databaseHelper.addObject("" +
                "role:          First Role\n" +
                "address:       Singel 258\n" +
                "e-mail:        dbtest@ripe.net\n" +
                "admin-c:       PP1-TEST\n" +
                "tech-c:        PP1-TEST\n" +
                "nic-hdl:       FR1-TEST\n" +
                "mnt-by:        OWNER-MNT\n" +
                "changed:       dbtest@ripe.net 20121016\n" +
                "source:        TEST\n");
        databaseHelper.addObject("" +
                "domain:        31.12.202.in-addr.arpa\n" +
                "descr:         Test domain\n" +
                "admin-c:       TP1-TEST\n" +
                "tech-c:        TP1-TEST\n" +
                "zone-c:        TP1-TEST\n" +
                "notify:        notify@test.net.au\n" +
                "nserver:       ns1.test.com.au 10.0.0.1\n" +
                "nserver:       ns2.test.com.au 2001:10::2\n" +
                "ds-rdata:      52151 1 1 13ee60f7499a70e5aadaf05828e7fc59e8e70bc1\n" +
                "ds-rdata:      17881 5 1 2e58131e5fe28ec965a7b8e4efb52d0a028d7a78\n" +
                "ds-rdata:      17881 5 2 8c6265733a73e5588bfac516a4fcfbe1103a544b95f254cb67a21e474079547e\n" +
                "changed:       test@test.net.au 20010816\n" +
                "changed:       test@test.net.au 20121121\n" +
                "mnt-by:        OWNER-MNT\n" +
                "source:        TEST\n");
        databaseHelper.addObject("" +
                "aut-num:       AS123\n" +
                "as-name:       AS-TEST\n" +
                "descr:         A single ASN\n" +
                "country:       AU\n" +
                "admin-c:       TP1-TEST\n" +
                "tech-c:        TP1-TEST\n" +
                "changed:       test@test.net.au 20010816\n" +
                "mnt-by:        OWNER-MNT\n" +
                "source:        TEST\n");
        databaseHelper.addObject("" +
                "aut-num:       AS1234\n" +
                "as-name:       AS-TEST\n" +
                "descr:         A single ASN\n" +
                "admin-c:       TP1-TEST\n" +
                "tech-c:        TP2-TEST\n" +
                "changed:       test@test.net.au 20010816\n" +
                "mnt-by:        OWNER-MNT\n" +
                "source:        TEST\n");

        databaseHelper.addObject("" +
                "organisation:  ORG-TEST1-TEST\n" +
                "org-name:      Test organisation\n" +
                "org-type:      OTHER\n" +
                "descr:         Drugs and gambling\n" +
                "remarks:       Nice to deal with generally\n" +
                "address:       1 Fake St. Fauxville\n" +
                "phone:         +01-000-000-000\n" +
                "fax-no:        +01-000-000-000\n" +
                "admin-c:       PP1-TEST\n" +
                "e-mail:        org@test.com\n" +
                "mnt-by:        OWNER-MNT\n" +
                "changed:       test@test.net.au 20121121\n" +
                "source:        TEST\n");
        databaseHelper.addObject("" +
                "organisation:  ORG-ONE-TEST\n" +
                "org-name:      Organisation One\n" +
                "org-type:      LIR\n" +
                "address:       One Org Street\n" +
                "               Fakeville\n" +
                "address:       USA\n" +
                "e-mail:        test@ripe.net\n" +
                "admin-c:       TP2-TEST\n" +
                "tech-c:        TP1-TEST\n" +
                "tech-c:        TP2-TEST\n" +
                "mnt-ref:       OWNER-MNT\n" +
                "mnt-by:        OWNER-MNT\n" +
                "changed:       test@test.net.au 20000228\n" +
                "abuse-mailbox: test@test.net.au\n" +
                "source:        TEST\n");
        databaseHelper.addObject("" +
                "as-block:       AS100 - AS200\n" +
                "descr:          ARIN ASN block\n" +
                "org:            ORG-TEST1-TEST\n" +
                "mnt-by:         OWNER-MNT\n" +
                "changed:        dbtest@ripe.net   20121214\n" +
                "source:         TEST\n" +
                "password:       test\n");
        ipTreeUpdater.rebuild();
        freeTextIndex.update();
        //Thread.sleep(10000000);
    }

    // inetnum

    @Before
    @Override
    public void setUpClient() throws Exception {
        ClientConfig cc = new DefaultClientConfig();
        cc.getSingletons().add(new RdapJsonProvider());
        client = Client.create(cc);
    }

    @Test
    public void lookup_nameserver() {
        try {
            createResource(AUDIENCE, "nameserver/asdf")
                    .accept(MediaType.APPLICATION_JSON_TYPE)
                    .get(Nameserver.class);
            fail();
        } catch (final UniformInterfaceException e) {
            assertThat(e.getResponse().getStatus(), is(501));
        }
    }

    @Test
    public void lookup_inetnum_range() {
        databaseHelper.addObject("" +
                "inetnum:      192.0.0.0 - 192.255.255.255\n" +
                "netname:      TEST-NET-NAME\n" +
                "descr:        TEST network\n" +
                "country:      NL\n" +
                "language:     en\n" +
                "tech-c:       TP1-TEST\n" +
                "status:       OTHER\n" +
                "mnt-by:       OWNER-MNT\n" +
                "changed:      dbtest@ripe.net 20020101\n" +
                "source:       TEST");
        ipTreeUpdater.rebuild();

        final Ip ip = createResource(AUDIENCE, "ip/192.0.0.0/8")
                .accept(MediaType.APPLICATION_JSON_TYPE)
                .get(Ip.class);

        assertThat(ip.getHandle(), is("192.0.0.0 - 192.255.255.255"));
        assertThat(ip.getIpVersion(), is("v4"));
        assertThat(ip.getCountry(), is("NL"));
        assertThat(ip.getStartAddress(), is("192.0.0.0"));
        assertThat(ip.getEndAddress(), is("192.255.255.255"));
        assertThat(ip.getName(), is("TEST-NET-NAME"));

        final List<Link> links = ip.getLinks();
        assertThat(links, hasSize(1));
        final String selfUrl = createResource(AUDIENCE, "ip/192.0.0.0/8").toString();
        assertThat(links.get(0).getRel(), equalTo("self"));
        assertThat(links.get(0).getHref(), equalTo(selfUrl));
        assertThat(links.get(0).getValue(), equalTo(selfUrl));

        final List<Event> events = ip.getEvents();
        assertThat(events, hasSize(1));
//        assertTrue(events.get(0).getEventDate().isBefore(LocalDateTime.now()));
        assertThat(events.get(0).getEventAction(), is("last changed"));

        final List<Notice> notices = ip.getNotices();
        /* todo: not set properly at the moment. */
        //assertThat(notices, hasSize(3));

        // For easy testing of unordered List<Object> values using xpath
        Document domIp = RdapHelperUtils.toDOM(ip);
        LOGGER.info(RdapHelperUtils.DOMToString(domIp));
        String prefixpath = "/" + Ip.class.getName() + "/notices/" + Notice.class.getName();


        // Use xpath <3 to test for presence of bean values in unordered list

        /* todo: Notice tests disabled temporarily. Need to fix test
         * properties. */
        /*
        Assert.assertThat(domIp, hasXPath(prefixpath + "/title[text() = 'Terms and Conditions']")); // Not really necessary but here for simple example
        Assert.assertThat(domIp, hasXPath(prefixpath + "/title[text() = 'Terms and Conditions']/../description/string[text() = 'This is the RIPE Database query service. The objects are in RDAP format.']"));

        Assert.assertThat(domIp, hasXPath(prefixpath + "/title[text() = 'Filtered']/../description/string[text() = 'This output has been filtered.']"));

        Assert.assertThat(domIp, hasXPath(prefixpath + "/title[text() = 'Source']/../description/string[text() = 'Objects returned came from source']"));
        Assert.assertThat(domIp, hasXPath(prefixpath + "/title[text() = 'Source']/../description/string[text() = 'TEST']"));
        */

          //  TODO: [ES] And so on....
//        assertThat(notices.get(0).getLinks(), is(nullValue()));
//        assertThat(notices.get(1).getTitle(), is("Source"));
//        assertThat(notices.get(1).getLinks(), is(nullValue()));
//        //assertThat(notices.get(2).getLinks().getValue(), endsWith("/rdap/ip/192.0.0.0/8"));
//        assertThat(notices.get(2).getLinks().getRel(), is("terms-of-service"));
//        assertThat(notices.get(2).getLinks().getHref(), is("http://www.ripe.net/db/support/db-terms-conditions.pdf"));
    }

    @Test
    public void lookup_inetnum_less_specific() {
        databaseHelper.addObject("" +
                "inetnum:      192.0.0.0 - 192.255.255.255\n" +
                "netname:      TEST-NET-NAME\n" +
                "descr:        TEST network\n" +
                "country:      NL\n" +
                "tech-c:       TP1-TEST\n" +
                "status:       OTHER\n" +
                "mnt-by:       OWNER-MNT\n" +
                "changed:      dbtest@ripe.net 20020101\n" +
                "source:       TEST");
        ipTreeUpdater.rebuild();

        final Ip ip = createResource(AUDIENCE, "ip/192.0.0.255")
                .accept(MediaType.APPLICATION_JSON_TYPE)
                .get(Ip.class);

        assertThat(ip.getHandle(), is("192.0.0.0 - 192.255.255.255"));
        assertThat(ip.getIpVersion(), is("v4"));
        assertThat(ip.getCountry(), is("NL"));
        assertThat(ip.getStartAddress(), is("192.0.0.0"));
        assertThat(ip.getEndAddress(), is("192.255.255.255"));
        assertThat(ip.getName(), is("TEST-NET-NAME"));
        assertThat(ip.getLang(), is(nullValue()));
        assertThat(ip.getParentHandle(), is(nullValue()));

        final List<Link> links = ip.getLinks();
        assertThat(links, hasSize(1));
        final String selfUrl = createResource(AUDIENCE, "ip/" + RdapObjectMapper.urlencode("192.0.0.0/8")).toString();
        assertThat(links.get(0).getRel(), equalTo("self"));
        assertThat(links.get(0).getHref(), equalTo(selfUrl));
        assertThat(links.get(0).getValue(), equalTo(selfUrl));
    }

    @Test
    public void lookup_inetnum_with_parent() {
        databaseHelper.addObject("" +
                "inetnum:      192.0.0.0 - 192.0.0.0\n" +
                "netname:      TEST-NET-NAME-32\n" +
                "descr:        TEST network\n" +
                "country:      NL\n" +
                "language:     en\n" +
                "tech-c:       TP1-TEST\n" +
                "status:       OTHER\n" +
                "mnt-by:       OWNER-MNT\n" +
                "changed:      dbtest@ripe.net 20020101\n" +
                "source:       TEST");
        databaseHelper.addObject("" +
                "inetnum:      192.0.0.0 - 192.0.0.255\n" +
                "netname:      TEST-NET-NAME-24\n" +
                "descr:        TEST network\n" +
                "country:      NL\n" +
                "language:     en\n" +
                "tech-c:       TP1-TEST\n" +
                "status:       OTHER\n" +
                "mnt-by:       OWNER-MNT\n" +
                "changed:      dbtest@ripe.net 20020101\n" +
                "source:       TEST");
        ipTreeUpdater.rebuild();

        final Ip response = createResource(AUDIENCE, "ip/192.0.0.0")
                .accept(MediaType.APPLICATION_JSON_TYPE)
                .get(Ip.class);

        assertThat(response.getHandle(), is("192.0.0.0 - 192.0.0.0"));
        assertThat(response.getIpVersion(), is("v4"));
        assertThat(response.getCountry(), is("NL"));
        assertThat(response.getStartAddress(), is("192.0.0.0"));
        assertThat(response.getEndAddress(), is("192.0.0.0"));
        assertThat(response.getName(), is("TEST-NET-NAME-32"));
        assertThat(response.getParentHandle(), is("192.0.0.0 - 192.0.0.255"));

        final List<Link> links = response.getLinks();
        assertThat(links, hasSize(2));
        final Link upLink = links.get(0);
        final String upUrl = createResource(AUDIENCE, "ip/" + RdapObjectMapper.urlencode("192.0.0.0/24")).toString();
        assertThat(upLink.getRel(), equalTo("up"));
        assertThat(upLink.getHref(), equalTo(upUrl));

        final Link selfLink = links.get(1);
        assertThat(selfLink.getRel(), equalTo("self"));
    }

    // inet6num

    @Test
    public void lookup_inetnum_not_found() {
        try {
            createResource(AUDIENCE, "ip/193.0.0.0")
                    .accept(MediaType.APPLICATION_JSON_TYPE)
                    .get(Ip.class);
            fail();
        } catch (final UniformInterfaceException e) {
            assertThat(e.getResponse().getStatus(), is(Response.Status.NOT_FOUND.getStatusCode()));
        }
    }

    @Test
    public void lookup_inetnum_invalid_syntax() {
        try {
            createResource(AUDIENCE, "ip/invalid")
                    .accept(MediaType.APPLICATION_JSON_TYPE)
                    .get(Ip.class);
        } catch (final UniformInterfaceException e) {
            assertThat(e.getResponse().getStatus(), is(Response.Status.BAD_REQUEST.getStatusCode()));
        }
    }

    // inet6num

    @Test
    public void lookup_inet6num_with_prefix_length() throws Exception {
        databaseHelper.addObject("" +
                "inet6num:       2001:2002:2003::/48\n" +
                "netname:        RIPE-NCC\n" +
                "descr:          Private Network\n" +
                "country:        NL\n" +
                "language:       EN\n" +
                "tech-c:         TP1-TEST\n" +
                "status:         ASSIGNED PA\n" +
                "mnt-by:         OWNER-MNT\n" +
                "mnt-lower:      OWNER-MNT\n" +
                "source:         TEST");
        ipTreeUpdater.rebuild();

        final Ip ip = createResource(AUDIENCE, "ip/2001:2002:2003::/48")
                .accept(MediaType.APPLICATION_JSON_TYPE)
                .get(Ip.class);

        assertThat(ip.getHandle(), is("2001:2002:2003::/48"));
        assertThat(ip.getIpVersion(), is("v6"));
        assertThat(ip.getCountry(), is("NL"));
        assertThat(ip.getStartAddress(), is("2001:2002:2003::"));
        assertThat(ip.getEndAddress(), is("2001:2002:2003:ffff:ffff:ffff:ffff:ffff"));
        assertThat(ip.getName(), is("RIPE-NCC"));
        assertThat(ip.getType(), is("ASSIGNED PA"));

        final List<Event> events = ip.getEvents();
        assertThat(events, hasSize(1));
//        assertTrue(events.get(0).getEventDate().isBefore(LocalDateTime.now()));
        assertThat(events.get(0).getEventAction(), is("last changed"));
    }

    // person entity

    @Test
    public void lookup_inet6num_less_specific() throws Exception {
        databaseHelper.addObject("" +
                "inet6num:       2001:2002:2003::/48\n" +
                "netname:        RIPE-NCC\n" +
                "descr:          Private Network\n" +
                "country:        NL\n" +
                "tech-c:         TP1-TEST\n" +
                "status:         ASSIGNED PA\n" +
                "mnt-by:         OWNER-MNT\n" +
                "mnt-lower:      OWNER-MNT\n" +
                "source:         TEST");
        ipTreeUpdater.rebuild();

        final Ip ip = createResource(AUDIENCE, "ip/2001:2002:2003:2004::")
                .accept(MediaType.APPLICATION_JSON_TYPE)
                .get(Ip.class);

        assertThat(ip.getHandle(), is("2001:2002:2003::/48"));
        assertThat(ip.getIpVersion(), is("v6"));
        assertThat(ip.getCountry(), is("NL"));
        assertThat(ip.getStartAddress(), is("2001:2002:2003::"));
        assertThat(ip.getEndAddress(), is("2001:2002:2003:ffff:ffff:ffff:ffff:ffff"));
        assertThat(ip.getName(), is("RIPE-NCC"));

        final List<Link> links = ip.getLinks();
        assertThat(links, hasSize(1));
        final String selfUrl = createResource(AUDIENCE, "ip/" + RdapObjectMapper.urlencode("2001:2002:2003::/48")).toString();
        assertThat(links.get(0).getRel(), equalTo("self"));
        assertThat(links.get(0).getHref(), equalTo(selfUrl));
        assertThat(links.get(0).getValue(), equalTo(selfUrl));
    }

    @Test
    public void lookup_inet6num_not_found() {
        try {
            createResource(AUDIENCE, "ip/2001:2002:2003::/48")
                    .accept(MediaType.APPLICATION_JSON_TYPE)
                    .get(Ip.class);
            fail();
        } catch (final UniformInterfaceException e) {
            assertThat(e.getResponse().getStatus(), is(Response.Status.NOT_FOUND.getStatusCode()));
        }
    }

    @Test
    public void lookup_inet6num_invalid_syntax() {
        try {
            createResource(AUDIENCE, "ip/%5B::%5D")
                    .accept(RdapJsonProvider.CONTENT_TYPE_RDAP_JSON)
                    .get(Ip.class);
        } catch (final UniformInterfaceException e) {
            final ClientResponse response = e.getResponse();
            assertThat(response.getStatus(), is(Response.Status.BAD_REQUEST.getStatusCode()));

            // Test content type
            assertThat(RdapJsonProvider.CONTENT_TYPE_RDAP_JSON, equalTo(response.getType().toString()));
        }
    }

    @Test
    public void lookup_person_entity() throws Exception {
        final Entity entity = createResource(AUDIENCE, "entity/PP1-TEST")
                .accept(MediaType.APPLICATION_JSON_TYPE)
                .get(Entity.class);

        assertEntityPP1_TEST(entity);
    }

    @Test
    public void lookup_entity_no_accept_header() throws Exception {
        final WebResource webResource = createResource(AUDIENCE, "entity/PP1-TEST");

        // Get using HttpClient so there is no accept header
        RdapHelperUtils.HttpResponseElements response = RdapHelperUtils.getHttpHeaderAndContent(webResource.getURI().toASCIIString());

        // Get Response Body
        String responseBody = new String(response.body);
        LOGGER.info("Response=" + responseBody);

        // Test content type
        Header[] headers = response.headers;
        String contentType = checkHeaderPresent(CONTENT_TYPE_HEADER, headers);
        assertEquals(RdapJsonProvider.CONTENT_TYPE_RDAP_JSON, contentType);

        Entity entity = RdapHelperUtils.unmarshal(responseBody, Entity.class);
        assertEntityPP1_TEST(entity);

        String[] utcEventDates = StringUtils.substringsBetween(responseBody, "\"eventDate\"", "Z");
        assertThat("Event Dates must be UTC", utcEventDates.length == 1);
    }

    @Test
    public void lookup_entity_with_firefox_browser() throws Exception {

        final WebResource webResource = createResource(AUDIENCE, "entity/PP1-TEST");

        // Get using HttpClient with content-type set like firefox
        Header headerEntry = new Header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
        RdapHelperUtils.HttpResponseElements response = RdapHelperUtils.getHttpHeaderAndContent(webResource.getURI().toASCIIString(), false, headerEntry);
        String responseBody = new String(response.body);
        LOGGER.info("Response=" + responseBody);

        // Test content type
        Header[] headers = response.headers;
        String contentType = checkHeaderPresent(CONTENT_TYPE_HEADER, headers);
        assertEquals(MediaType.TEXT_PLAIN, contentType);

        Entity entity = RdapHelperUtils.unmarshal(responseBody, Entity.class);
        assertEntityPP1_TEST(entity);

        String[] utcEventDates = StringUtils.substringsBetween(responseBody, "\"eventDate\"", "Z");
        assertThat("Event Dates must be UTC", utcEventDates.length == 1);
    }


    @Test
    public void lookup_entity_with_application_json() throws Exception {
        final WebResource webResource = createResource(AUDIENCE, "entity/PP1-TEST");

        // Get using HttpClient with content-type set like firefox
        Header headerEntry = new Header("Accept", MediaType.APPLICATION_JSON);
        RdapHelperUtils.HttpResponseElements response = RdapHelperUtils.getHttpHeaderAndContent(webResource.getURI().toASCIIString(), false, headerEntry);
        String responseBody = new String(response.body);
        LOGGER.info("Response=" + responseBody);

        // Test content type
        Header[] headers = response.headers;
        String contentType = checkHeaderPresent(CONTENT_TYPE_HEADER, headers);
        assertEquals(RdapJsonProvider.CONTENT_TYPE_RDAP_JSON, contentType);

        Entity entity = RdapHelperUtils.unmarshal(responseBody, Entity.class);
        assertEntityPP1_TEST(entity);

        String[] utcEventDates = StringUtils.substringsBetween(responseBody, "\"eventDate\"", "Z");
        assertThat("Event Dates must be UTC", utcEventDates.length == 1);
    }

    @Test
    public void lookup_entity_not_found() throws Exception {
        try {
            createResource(AUDIENCE, "entity/ORG-BAD1-TEST")
                    .accept(MediaType.APPLICATION_JSON_TYPE)
                    .get(Entity.class);
        } catch (final UniformInterfaceException e) {
            assertThat(e.getResponse().getStatus(), is(Response.Status.NOT_FOUND.getStatusCode()));
        }
    }

    @Test
    public void lookup_entity_invalid_syntax() throws Exception {
        try {
            createResource(AUDIENCE, "entity/12345")
                    .accept(MediaType.APPLICATION_JSON_TYPE)
                    .get(Entity.class);
            fail();
        } catch (UniformInterfaceException e) {
            assertThat(e.getResponse().getStatus(), is(Response.Status.BAD_REQUEST.getStatusCode()));
        }
    }

    // role entity

    @Test
    public void lookup_role_entity() throws Exception {
        final Entity entity = createResource(AUDIENCE, "entity/FR1-TEST")
                .accept(MediaType.APPLICATION_JSON_TYPE)
                .get(Entity.class);

        assertThat(entity.getHandle(), equalTo("FR1-TEST"));
        assertThat(entity.getVcardArray().size(), is(2));
        assertThat(entity.getVcardArray().get(0).toString(), is("vcard"));
        assertThat(entity.getVcardArray().get(1).toString(), equalTo("" +
                "[[version, {}, text, 4.0], " +
                "[fn, {}, text, First Role], " +
                "[kind, {}, text, group], " +
                "[adr, {label=Singel 258}, text, [, , , , , , ]], " +
                "[email, {}, text, dbtest@ripe.net]]"));
        /* todo: Not set at the moment. */
        //assertThat(entity.getPort43(), is("whois.ripe.net"));

        assertThat(entity.getEntities(), hasSize(1));
        assertThat(entity.getEntities().get(0).getHandle(), is("PP1-TEST"));
        assertThat(entity.getEntities().get(0).getRoles(), containsInAnyOrder(Role.ADMINISTRATIVE, Role.TECHNICAL));
        assertThat(entity.getRdapConformance(), hasSize(1));
        assertThat(entity.getRdapConformance().get(0), equalTo("rdap_level_0"));

        final List<Event> events = entity.getEvents();
        assertThat(events, hasSize(1));
//        assertTrue(events.get(0).getEventDate().isBefore(LocalDateTime.now()));
        assertThat(events.get(0).getEventAction(), is("last changed"));
    }

    // domain

    @Test
    public void lookup_domain_object() throws Exception {
        final Domain domain = createResource(AUDIENCE, "domain/31.12.202.in-addr.arpa")
                .accept(MediaType.APPLICATION_JSON_TYPE)
                .get(Domain.class);

        assertThat(domain.getHandle(), equalTo("31.12.202.in-addr.arpa"));
        assertThat(domain.getLdhName(), equalTo("31.12.202.in-addr.arpa"));
        assertThat(domain.getRdapConformance(), hasSize(1));
        assertThat(domain.getRdapConformance().get(0), equalTo("rdap_level_0"));
        /* todo: Not set at the moment. */
        //assertThat(domain.getPort43(), is("whois.ripe.net"));

        final List<Event> events = domain.getEvents();
        assertThat(events, hasSize(1));
//        assertTrue(events.get(0).getEventDate().isBefore(LocalDateTime.now()));
        assertThat(events.get(0).getEventAction(), is("last changed"));
    }

    @Test
    public void domain_not_found() throws Exception {
        try {
            createResource(AUDIENCE, "domain/10.in-addr.arpa")
                    .accept(MediaType.APPLICATION_JSON_TYPE)
                    .get(Domain.class);
            fail();
        } catch (UniformInterfaceException e) {
            assertThat(e.getResponse().getStatus(), is(Response.Status.NOT_FOUND.getStatusCode()));
        }
    }


    @Test
    public void lookup_forward_domain() {
        try {
            createResource(AUDIENCE, "domain/ripe.net")
                    .accept(MediaType.APPLICATION_JSON_TYPE)
                    .get(Domain.class);
            fail();
        } catch (UniformInterfaceException e) {
            assertThat(e.getResponse().getStatus(), is(Response.Status.BAD_REQUEST.getStatusCode()));
            assertThat(e.getResponse().getEntity(net.ripe.db.whois.api.whois.rdap.domain.Error.class).getErrorCode(), is(Response.Status.BAD_REQUEST.getStatusCode()));
        }
    }

    @Test
    public void invalid_domain() throws Exception {
        try {
            createResource(AUDIENCE, "domain/shazzbot")
                    .accept(MediaType.APPLICATION_JSON_TYPE)
                    .get(Domain.class);
            fail();
        } catch (UniformInterfaceException e) {
            assertThat(e.getResponse().getStatus(), is(Response.Status.BAD_REQUEST.getStatusCode()));
            assertThat(e.getResponse().getEntity(net.ripe.db.whois.api.whois.rdap.domain.Error.class).getErrorCode(), is(Response.Status.BAD_REQUEST.getStatusCode()));
        }
    }

    @Test
    public void invalid_ip() throws Exception {
        try {
            createResource(AUDIENCE, "ip/eyepee")
                    .accept(MediaType.APPLICATION_JSON_TYPE)
                    .get(Ip.class);
            fail();
        } catch (UniformInterfaceException e) {
            assertThat(e.getResponse().getStatus(), is(Response.Status.BAD_REQUEST.getStatusCode()));
            assertThat(e.getResponse().getEntity(net.ripe.db.whois.api.whois.rdap.domain.Error.class).getErrorCode(), is(Response.Status.BAD_REQUEST.getStatusCode()));
        }
    }


    @Test
    public void invalid_entity() throws Exception {
        try {
            createResource(AUDIENCE, "entity/OWNER-MNT")
                    .accept(MediaType.APPLICATION_JSON_TYPE)
                    .get(Entity.class);
            fail();
        } catch (UniformInterfaceException e) {
            assertThat(e.getResponse().getStatus(), is(Response.Status.BAD_REQUEST.getStatusCode()));
            assertThat(e.getResponse().getEntity(net.ripe.db.whois.api.whois.rdap.domain.Error.class).getErrorCode(), is(Response.Status.BAD_REQUEST.getStatusCode()));
        }
    }

    @Test
    public void invalid_autnum() throws Exception {
        try {
            createResource(AUDIENCE, "autnum/as1")
                    .accept(MediaType.APPLICATION_JSON_TYPE)
                    .get(Autnum.class);
            fail();
        } catch (UniformInterfaceException e) {
            assertThat(e.getResponse().getStatus(), is(Response.Status.BAD_REQUEST.getStatusCode()));
            assertThat(e.getResponse().getEntity(net.ripe.db.whois.api.whois.rdap.domain.Error.class).getErrorCode(), is(Response.Status.BAD_REQUEST.getStatusCode()));
        }
    }

    @Test
    public void autnum_not_found() throws Exception {
        try {
            createResource(AUDIENCE, "autnum/1")
                    .accept(MediaType.APPLICATION_JSON_TYPE)
                    .get(Autnum.class);
            fail();
        } catch (UniformInterfaceException e) {
            assertThat(e.getResponse().getStatus(), is(Response.Status.NOT_FOUND.getStatusCode()));
        }
    }

    @Test
    public void autnum_invalid_syntax() throws Exception {
        try {
            createResource(AUDIENCE, "autnum/XYZ")
                    .accept(MediaType.APPLICATION_JSON_TYPE)
                    .get(Autnum.class);
            fail();
        } catch (UniformInterfaceException e) {
            assertThat(e.getResponse().getStatus(), is(Response.Status.BAD_REQUEST.getStatusCode()));
        }
    }

    @Test
    public void lookup_autnum_head_method() {
        final ClientResponse response = createResource(AUDIENCE, "autnum/123").head();

        assertThat(response.getStatus(), is(Response.Status.OK.getStatusCode()));
    }

    @Test
    public void lookup_autnum_not_found_head_method() {
        final ClientResponse response = createResource(AUDIENCE, "autnum/1").head();

        assertThat(response.getStatus(), is(Response.Status.NOT_FOUND.getStatusCode()));
    }

    @Test
    public void lookup_single_autnum_AS123() throws Exception {
        final Autnum autnum = createResource(AUDIENCE, "autnum/123")
                .accept(MediaType.APPLICATION_JSON_TYPE)
                .get(Autnum.class);

        assertThat(autnum.getHandle(), equalTo("AS123"));
        assertThat(autnum.getStartAutnum(), equalTo(123L));
        assertThat(autnum.getEndAutnum(), equalTo(123L));
        assertThat(autnum.getName(), equalTo("AS-TEST"));
        assertThat(autnum.getCountry(), equalTo("AU"));

        final List<Event> events = autnum.getEvents();
        assertThat(events, hasSize(1));
//        assertTrue(events.get(0).getEventDate().isBefore(LocalDateTime.now()));
        assertThat(events.get(0).getEventAction(), is("last changed"));

        final List<Entity> entities = autnum.getEntities();
        assertThat(entities, hasSize(1));
        assertThat(entities.get(0).getHandle(), is("TP1-TEST"));
        assertThat(entities.get(0).getRoles(), hasSize(2));
        assertThat(entities.get(0).getRoles(), containsInAnyOrder(Role.ADMINISTRATIVE, Role.TECHNICAL));

        final List<Link> links = autnum.getLinks();
        assertThat(links, hasSize(1));
        final Link selfLink = links.get(0);
        assertThat(selfLink.getRel(), equalTo("self"));

        final String ru = createResource(AUDIENCE, "autnum/123").toString();
        assertThat(selfLink.getValue(), equalTo(ru));
        assertThat(selfLink.getHref(), equalTo(ru));

        final List<Remark> remarks = autnum.getRemarks();
        assertThat(remarks, hasSize(1));
        assertThat(remarks.get(0).getDescription().get(0), is("A single ASN"));
    }

    @Test
    public void lookup_single_autnum_AS1234() throws Exception {
        final Autnum autnum = createResource(AUDIENCE, "autnum/1234")
                .accept(MediaType.APPLICATION_JSON_TYPE)
                .get(Autnum.class);

        assertThat(autnum.getHandle(), equalTo("AS1234"));
        assertThat(autnum.getStartAutnum(), equalTo(1234L));
        assertThat(autnum.getEndAutnum(), equalTo(1234L));
        assertThat(autnum.getName(), equalTo("AS-TEST"));

        final List<Event> events = autnum.getEvents();
        assertThat(events, hasSize(1));
//        assertTrue(events.get(0).getEventDate().isBefore(LocalDateTime.now()));
        assertThat(events.get(0).getEventAction(), is("last changed"));


        final List<SortedEntity> entities = SortedEntity.createSortedEntities(autnum.getEntities());
        assertThat(entities, hasSize(2));

        assertThat(entities.get(0).getHandle(), is("TP1-TEST"));
        assertThat(entities.get(0).getRoles(), hasSize(1));
        assertThat(entities.get(0).getRoles(), contains(Role.ADMINISTRATIVE));

        assertThat(entities.get(1).getHandle(), is("TP2-TEST"));
        assertThat(entities.get(1).getRoles(), hasSize(1));
        assertThat(entities.get(1).getRoles(), contains(Role.TECHNICAL));

        final List<Link> links = autnum.getLinks();
        assertThat(links, hasSize(1));
        final Link selfLink = links.get(0);
        assertThat(selfLink.getRel(), equalTo("self"));

        final String ru = createResource(AUDIENCE, "autnum/1234").toString();
        assertThat(selfLink.getValue(), equalTo(ru));
        assertThat(selfLink.getHref(), equalTo(ru));

        final List<Remark> remarks = autnum.getRemarks();
        assertThat(remarks, hasSize(1));
        assertThat(remarks.get(0).getDescription().get(0), is("A single ASN"));
    }

    @Test
    public void lookup_as_block() throws Exception {
        final Autnum autnum = createResource(AUDIENCE, "autnum/150")
                .accept(MediaType.APPLICATION_JSON_TYPE)
                .get(Autnum.class);

        assertThat(autnum.getHandle(), equalTo("AS100 - AS200"));
        assertThat(autnum.getStartAutnum(), equalTo(100L));
        assertThat(autnum.getEndAutnum(), equalTo(200L));
        assertThat(autnum.getName(), equalTo("AS100 - AS200"));

        final List<Event> events = autnum.getEvents();
        assertThat(events, hasSize(1));
        final Event lastEvent = events.get(0);
        assertThat(lastEvent.getEventAction(), is("last changed"));

        final List<Link> links = autnum.getLinks();
        assertThat(links, hasSize(1));
        final Link selfLink = links.get(0);
        assertThat(selfLink.getRel(), equalTo("self"));

        final String ru = createResource(AUDIENCE, "autnum/150").toString();
        assertThat(selfLink.getValue(), equalTo(ru));
        assertThat(selfLink.getHref(), equalTo(ru));

        final List<Remark> remarks = autnum.getRemarks();
        assertThat(remarks, hasSize(1));
        assertThat(remarks.get(0).getDescription().get(0), is("ARIN ASN block"));
    }

    @Test
    public void lookup_autnum_within_block() throws Exception {
        try {
            createResource(AUDIENCE, "autnum/1500")
                    .accept(MediaType.APPLICATION_JSON_TYPE)
                    .get(Autnum.class);
            fail();
        } catch (UniformInterfaceException e) {
            assertThat(e.getResponse().getStatus(), is(Response.Status.NOT_FOUND.getStatusCode()));
        }
    }

    // general

    @Test
    public void lookup_autnum_with_rdap_json_content_type() {
        final ClientResponse response = createResource(AUDIENCE, "autnum/123")
                .accept(RdapJsonProvider.CONTENT_TYPE_RDAP_JSON)
                .get(ClientResponse.class);

        assertThat(response.getType(), is(RdapJsonProvider.CONTENT_TYPE_RDAP_JSON_TYPE));
        assertThat(response.getEntity(String.class), containsString("\"handle\" : \"AS123\""));
    }

    @Test
    public void multiple_modification_gives_correct_events() throws Exception {
        final String rpslObject = "" +
                "aut-num:   AS123\n" +
                "as-name:   AS-TEST\n" +
                "descr:     Modified ASN\n" +
                "admin-c:   TP1-TEST\n" +
                "tech-c:    TP1-TEST\n" +
                "changed:   test@test.net.au 20010816\n" +
                "mnt-by:    OWNER-MNT\n" +
                "source:    TEST\n" +
                "password:  test\n";
        final String response = syncupdate(rpslObject);
        assertThat(response, containsString("Modify SUCCEEDED: [aut-num] AS123"));

        final String deleteString = "" +
                "aut-num:   AS123\n" +
                "as-name:   AS-TEST\n" +
                "descr:     Modified ASN\n" +
                "admin-c:   TP1-TEST\n" +
                "tech-c:    TP1-TEST\n" +
                "changed:   test@test.net.au 20010816\n" +
                "mnt-by:    OWNER-MNT\n" +
                "source:    TEST\n" +
                "delete:    reason\n" +
                "password:  test\n";

        final String delete = doPostOrPutRequest(getSyncupdatesUrl("test", ""), "POST", "DATA=" + encode(deleteString), MediaType.APPLICATION_FORM_URLENCODED, HttpURLConnection.HTTP_OK);
        assertThat(delete, containsString("Delete SUCCEEDED: [aut-num] AS123"));

        final String recreate = doPostOrPutRequest(getSyncupdatesUrl("test", ""), "POST", "DATA=" + encode(rpslObject) + "&NEW=yes", MediaType.APPLICATION_FORM_URLENCODED, HttpURLConnection.HTTP_OK);
        assertThat(recreate, containsString("Create SUCCEEDED: [aut-num] AS123"));

        final String modifiedAgain = "" +
                "aut-num:   AS123\n" +
                "as-name:   AS-TEST\n" +
                "descr:     Final version ASN\n" +
                "admin-c:   TP1-TEST\n" +
                "tech-c:    TP1-TEST\n" +
                "changed:   test@test.net.au 20010816\n" +
                "mnt-by:    OWNER-MNT\n" +
                "source:    TEST\n" +
                "password:  test\n";
        final String last = doPostOrPutRequest(getSyncupdatesUrl("test", ""), "POST", "DATA=" + encode(modifiedAgain), MediaType.APPLICATION_FORM_URLENCODED, HttpURLConnection.HTTP_OK);
        assertThat(last, containsString("Modify SUCCEEDED: [aut-num] AS123"));

        final Autnum autnum = createResource(AUDIENCE, "autnum/123")
                .accept(MediaType.APPLICATION_JSON_TYPE)
                .get(Autnum.class);

        final List<Event> events = autnum.getEvents();
        assertThat(events, hasSize(1));
        assertThat(events.get(0).getEventAction(), is("last changed"));
//        assertTrue(events.get(0).getEventDate().isBefore(LocalDateTime.now()));
    }

    @Test
    public void lookup_inetnum_abuse_contact_as_vcard() {
        databaseHelper.addObject("" +
                "role:          Abuse Contact\n" +
                "address:       Singel 258\n" +
                "phone:         +31 6 12345678\n" +
                "nic-hdl:       AB-TEST\n" +
                "abuse-mailbox: abuse@test.net\n" +
                "mnt-by:        OWNER-MNT\n" +
                "changed:       dbtest@ripe.net 20120101\n" +
                "source:        TEST\n");
        databaseHelper.addObject("" +
                "irt:           IRT-TEST1-MNT\n" +
                "descr:         Owner Maintainer\n" +
                "admin-c:       TP1-TEST\n" +
                "e-mail:        info@test.net\n" +
                "abuse-mailbox: abuse@test.net\n" +
                "mnt-by:        OWNER-MNT\n" +
                "changed:       dbtest@ripe.net 20120101\n" +
                "source:        TEST\n");
        databaseHelper.addObject("" +
                "organisation:  ORG-TO2-TEST\n" +
                "org-name:      Test organisation\n" +
                "org-type:      OTHER\n" +
                "abuse-c:       AB-TEST\n" +
                "descr:         Drugs and gambling\n" +
                "remarks:       Nice to deal with generally\n" +
                "address:       1 Fake St. Fauxville\n" +
                "phone:         +01-000-000-000\n" +
                "fax-no:        +01-000-000-000\n" +
                "e-mail:        org@test.com\n" +
                "mnt-by:        OWNER-MNT\n" +
                "changed:       test@test.net.au 20121121\n" +
                "source:        TEST\n");
        databaseHelper.addObject("" +
                "inetnum:      192.0.0.0 - 192.255.255.255\n" +
                "netname:      TEST-NET-NAME\n" +
                "descr:        TEST network\n" +
                "org:          ORG-TO2-TEST\n" +
                "country:      NL\n" +
                "tech-c:       TP1-TEST\n" +
                "status:       OTHER\n" +
                "mnt-by:       OWNER-MNT\n" +
                "changed:      dbtest@ripe.net 20020101\n" +
                "source:       TEST");
        databaseHelper.addObject("" +
                "inetnum:      192.0.0.0 - 192.0.0.255\n" +
                "netname:      TEST-NET-NAME\n" +
                "descr:        TEST network\n" +
                "country:      NL\n" +
                "tech-c:       TP1-TEST\n" +
                "status:       OTHER\n" +
                "mnt-by:       OWNER-MNT\n" +
                "mnt-irt:      IRT-TEST1-MNT\n" +
                "changed:      dbtest@ripe.net 20020101\n" +
                "source:       TEST");
        ipTreeUpdater.rebuild();

        final Ip ip = createResource(AUDIENCE, "ip/192.0.0.128")
                .accept(MediaType.APPLICATION_JSON_TYPE)
                .get(Ip.class);

        assertThat(ip.getEntities(), hasSize(3));

        Entity abuseContact = ip.getEntities().get(0);
        assertThat(abuseContact.getRoles().get(0), is(Role.ABUSE));

        assertThat(abuseContact.getHandle(), is("AB-TEST"));
        assertThat(abuseContact.getVcardArray(), hasSize(2));
        assertThat(abuseContact.getVcardArray().get(0).toString(), is("vcard"));
        assertThat(abuseContact.getVcardArray().get(1).toString(), is("" +
                "[[version, {}, text, 4.0], " +
                "[fn, {}, text, Abuse Contact], " +
                "[kind, {}, text, group], " +
                "[adr, {label=Singel 258}, text, [, , , , , , ]], " +
                "[tel, {type=voice}, text, +31 6 12345678]]"));

        Entity irt = ip.getEntities().get(1);
        assertThat(irt.getRoles().get(0), is(Role.ABUSE));

        assertThat(irt.getHandle(), is("IRT-TEST1-MNT"));
        assertThat(irt.getVcardArray(), hasSize(2));
        assertThat(irt.getVcardArray().get(0).toString(), is("vcard"));
        assertThat(irt.getVcardArray().get(1).toString(), is("" +
                "[[version, {}, text, 4.0], " +
                "[fn, {}, text, IRT-TEST1-MNT], " +
                "[kind, {}, text, group], " +
                "[email, {pref=1}, text, abuse@test.net], " +
                "[email, {}, text, info@test.net]]"));

        Entity techc = ip.getEntities().get(2);
        assertThat(techc.getRoles().get(0), is(Role.TECHNICAL));

        assertThat(techc.getHandle(), is("TP1-TEST"));
        assertThat(techc.getVcardArray(), hasSize(2));
        assertThat(techc.getVcardArray().get(0).toString(), is("vcard"));
        assertThat(techc.getVcardArray().get(1).toString(), is("" +
                "[[version, {}, text, 4.0], " +
                "[fn, {}, text, Test Person], " +
                "[kind, {}, text, individual], " +
                "[adr, {label=Singel 258}, text, [, , , , , , ]], " +
                "[tel, {type=voice}, text, +31 6 12345678]]"));

    }

    // organisation entity

    @Ignore("need to get Jetty to compact paths")
    @Test
    public void lookup_org_double_slash_entity_handle() throws Exception {
        final Entity response = createResource(AUDIENCE, "/entity/ORG-TEST1-TEST")
                .accept(MediaType.APPLICATION_JSON_TYPE)
                .get(Entity.class);

        assertThat(response.getHandle(), equalTo("ORG-TEST1-TEST"));
    }

    @Test
    public void lookup_org_entity_handle() throws Exception {
        final Entity response = createResource(AUDIENCE, "entity/ORG-TEST1-TEST")
                .accept(MediaType.APPLICATION_JSON_TYPE)
                .get(Entity.class);

        assertThat(response.getHandle(), equalTo("ORG-TEST1-TEST"));
    }

    @Test
    public void lookup_org_not_found() throws Exception {
        try {
            createResource(AUDIENCE, "entity/ORG-NONE-TEST")
                    .accept(MediaType.APPLICATION_JSON_TYPE)
                    .get(Entity.class);
            fail();
        } catch (UniformInterfaceException e) {
            assertThat(e.getResponse().getStatus(), is(Response.Status.NOT_FOUND.getStatusCode()));
        }
    }

    @Test
    public void lookup_org_invalid_syntax() throws Exception {
        try {
            createResource(AUDIENCE, "entity/ORG-INVALID")
                    .accept(MediaType.APPLICATION_JSON_TYPE)
                    .get(Entity.class);
            fail();
        } catch (UniformInterfaceException e) {
            assertThat(e.getResponse().getStatus(), is(Response.Status.BAD_REQUEST.getStatusCode()));
        }
    }

    @Test
    public void lookup_org_entity() throws Exception {
        databaseHelper.updateObject("" +
                "organisation:  ORG-ONE-TEST\n" +
                "org-name:      Organisation One\n" +
                "org-type:      LIR\n" +
                "descr:         Test organisation\n" +
                "address:       One Org Street\n" +
                "e-mail:        test@ripe.net\n" +
                "language:      EN\n" +
                "admin-c:       TP2-TEST\n" +
                "tech-c:        TP1-TEST\n" +
                "tech-c:        TP2-TEST\n" +
                "mnt-ref:       OWNER-MNT\n" +
                "mnt-by:        OWNER-MNT\n" +
                "changed:       test@test.net.au 20000228\n" +
                "source:        TEST\n");

        final Entity entity = createResource(AUDIENCE, "entity/ORG-ONE-TEST")
                .accept(MediaType.APPLICATION_JSON_TYPE)
                .get(Entity.class);

        assertThat(entity.getHandle(), equalTo("ORG-ONE-TEST"));
        assertThat(entity.getRoles(), hasSize(0));
        /* todo: Not set at the moment. */
        //assertThat(entity.getPort43(), is("whois.ripe.net"));

//        final List<Event> events = entity.getEvents();
//        assertThat(events.size(), equalTo(1));
//
//        final Event event = events.get(0);
//        assertThat(event.getEventDate().toString(), equalTo(""));

        assertThat(entity.getEvents().size(), equalTo(1));
        final Event event = entity.getEvents().get(0);
//        assertTrue(event.getEventDate().isBefore(LocalDateTime.now()));
        assertThat(event.getEventAction(), equalTo("last changed"));

        final List<SortedEntity> entities = SortedEntity.createSortedEntities(entity.getEntities());
        assertThat(entity.getEntities(), hasSize(2));
        assertThat(entities.get(0).getHandle(), is("TP1-TEST"));
        assertThat(entities.get(0).getRoles(), contains(Role.TECHNICAL));
        assertThat(entities.get(1).getHandle(), is("TP2-TEST"));
        assertThat(entities.get(1).getRoles(), containsInAnyOrder(Role.ADMINISTRATIVE, Role.TECHNICAL));

        final String orgLink = createResource(AUDIENCE, "entity/ORG-ONE-TEST").toString();
        final String tp1Link = createResource(AUDIENCE, "entity/TP1-TEST").toString();
        final String tp2Link = createResource(AUDIENCE, "entity/TP2-TEST").toString();

        assertThat(entities.get(0).getLinks(), hasSize(1));
        assertThat(entities.get(0).getLinks().get(0).getRel(), is("self"));
        assertThat(entities.get(0).getLinks().get(0).getValue(), is(orgLink));
        assertThat(entities.get(0).getLinks().get(0).getHref(), is(tp1Link));
        assertThat(entities.get(1).getLinks(), hasSize(1));
        assertThat(entities.get(1).getLinks().get(0).getRel(), is("self"));
        assertThat(entities.get(1).getLinks().get(0).getValue(), is(orgLink));
        assertThat(entities.get(1).getLinks().get(0).getHref(), is(tp2Link));

        /* todo: Notice tests disabled temporarily. Need to fix test
         * properties. */
        /*
        final List<Notice> notices = entity.getNotices();
        assertThat(notices.get(0).getLinks().get(0).getHref(), equalTo("http://www.ripe.net/db/support/db-terms-conditions.pdf"));
        assertThat(notices.get(0).getLinks().get(0).getValue(), equalTo(orgLink));
        assertThat(notices.get(0).getLinks().get(0).getRel(), equalTo("terms-of-service"));
        assertThat(notices.get(0).getTitle(), equalTo("Terms and Conditions"));
        */

        final List<SortedLink> links = SortedLink.createSortedLinks(entity.getLinks());
        assertThat(links, hasSize(1));
        assertThat(links.get(0).getRel(), equalTo("self"));
        assertThat(links.get(0).getValue(), equalTo(orgLink));
        assertThat(links.get(0).getHref(), equalTo(orgLink));

        assertThat(entity.getRemarks(), hasSize(1));
        assertThat(entity.getRemarks().get(0).getDescription(), contains("Test organisation"));

    }

    @Override
    protected WebResource createResource(final Audience audience, final String path) {
        WebResource resource = client.resource(String.format("http://localhost:%s/rdap/%s", getPort(audience), path));
        LOGGER.info("resource [" + resource.getURI().toASCIIString() + "]");
        return resource;
    }

    private String syncupdate(final String data) throws IOException {
        return doPostOrPutRequest(getSyncupdatesUrl("test", ""), "POST", "DATA=" + encode(data), MediaType.APPLICATION_FORM_URLENCODED, HttpURLConnection.HTTP_OK);
    }

    private String getSyncupdatesUrl(final String instance, final String command) {
        return "http://localhost:" + getPort(Audience.PUBLIC) + String.format("/whois/syncupdates/%s?%s", instance, command);
    }

    private static void assertNow(XMLGregorianCalendar eventDate) {
        XMLGregorianCalendar now = RdapObjectMapper.convertToXMLGregorianCalendar(LocalDateTime.now().withMillisOfSecond(0));
        long span = now.toGregorianCalendar().getTimeInMillis() - eventDate.toGregorianCalendar().getTimeInMillis();
        assertThat((int) span, is(lessThanOrEqualTo(1000)));
    }

    private void assertEntityPP1_TEST(Entity entity) {
        assertThat(entity.getHandle(), equalTo("PP1-TEST"));
        assertThat(entity.getEntities(), hasSize(0));
        assertThat(entity.getVcardArray().size(), is(2));
        assertThat(entity.getVcardArray().get(0).toString(), is("vcard"));
        assertThat(entity.getVcardArray().get(1).toString(), equalTo("" +
                "[[version, {}, text, 4.0], " +
                "[fn, {}, text, Pauleth Palthen], " +
                "[kind, {}, text, individual], " +
                "[adr, {label=Singel 258}, text, [, , , , , , ]], " +
                "[tel, {type=voice}, text, +31-1234567890], " +
                "[email, {}, text, noreply@ripe.net]]"));
        assertThat(entity.getRdapConformance(), hasSize(1));
        assertThat(entity.getRdapConformance().get(0), equalTo("rdap_level_0"));

        final List<Event> events = entity.getEvents();
        assertThat(events, hasSize(1));
//        assertTrue(events.get(0).getEventDate().isBefore(LocalDateTime.now()));
        assertThat(events.get(0).getEventAction(), is("last changed"));
    }


    private String checkHeaderPresent(String contentTypeHeader, Header[] headers) {
        String contentType = null;
        for (Header header : headers) {
            for (HeaderElement headerElement : header.getElements()) {
                LOGGER.info("Response Header: " + header.getName() + ":" + headerElement.getName());
                if (header.getName().equals(contentTypeHeader)) {
                    contentType = headerElement.getName();
                    break;
                }
            }
        }
        return contentType;
    }

}
