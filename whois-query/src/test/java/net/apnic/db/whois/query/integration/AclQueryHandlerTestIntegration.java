package net.apnic.db.whois.query.integration;

import net.ripe.db.whois.common.IntegrationTest;
import net.ripe.db.whois.common.rpsl.RpslObject;
import net.ripe.db.whois.common.support.DummyWhoisClient;
import net.ripe.db.whois.query.QueryServer;
import net.ripe.db.whois.query.support.AbstractWhoisIntegrationTest;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

@Category(IntegrationTest.class)
public class AclQueryHandlerTestIntegration extends AbstractWhoisIntegrationTest {

    @Before
    public void setup() {
        queryServer.start();
    }

    @After
    public void teardown() {
        queryServer.stop(true);
    }

    @Test
    public void testAclQueryLimits() {
        // Setup data
        rpslObjectUpdateDao.createObject(RpslObject.parse("mntner: MNT-USED-EVERYWHERE"));
        rpslObjectUpdateDao.createObject(RpslObject.parse("person: Test Testington\nnic-hdl: TT01-AP"));
        for (int i = 0; i < 2; i++) {
            for (int j = 0; j < 2; j++) {
                rpslObjectUpdateDao.createObject(RpslObject.parse(String.format("domain: %d.%d.in-addr.arpa\n" +
                        "mnt-by: MNT-USED-EVERYWHERE\n" +
                        "admin-c: TT01-AP\ntech-c: TT01-AP", i, j)));
            }
        }

        ipResourceConfiguration.reload();
        ipTreeUpdater.rebuild();

        // Test no query limits
        final String fullResponse = DummyWhoisClient.query(QueryServer.port, "-i mb MNT-USED-EVERYWHERE");
        assertEquals("" +
                "% [whois.apnic.net]\n" +
                "% Whois data copyright terms    http://www.apnic.net/db/dbcopyright.html\n" +
                "\n" +
                "% Information related to '0.0.in-addr.arpa'\n" +
                "\n" +
                "domain:         0.0.in-addr.arpa\n" +
                "mnt-by:         MNT-USED-EVERYWHERE\n" +
                "admin-c:        TT01-AP\n" +
                "tech-c:         TT01-AP\n" +
                "\n" +
                "person:         Test Testington\n" +
                "nic-hdl:        TT01-AP\n" +
                "\n" +
                "% Information related to '0.1.in-addr.arpa'\n" +
                "\n" +
                "domain:         0.1.in-addr.arpa\n" +
                "mnt-by:         MNT-USED-EVERYWHERE\n" +
                "admin-c:        TT01-AP\n" +
                "tech-c:         TT01-AP\n" +
                "\n" +
                "person:         Test Testington\n" +
                "nic-hdl:        TT01-AP\n" +
                "\n" +
                "% Information related to '1.0.in-addr.arpa'\n" +
                "\n" +
                "domain:         1.0.in-addr.arpa\n" +
                "mnt-by:         MNT-USED-EVERYWHERE\n" +
                "admin-c:        TT01-AP\n" +
                "tech-c:         TT01-AP\n" +
                "\n" +
                "person:         Test Testington\n" +
                "nic-hdl:        TT01-AP\n" +
                "\n" +
                "% Information related to '1.1.in-addr.arpa'\n" +
                "\n" +
                "domain:         1.1.in-addr.arpa\n" +
                "mnt-by:         MNT-USED-EVERYWHERE\n" +
                "admin-c:        TT01-AP\n" +
                "tech-c:         TT01-AP\n" +
                "\n" +
                "person:         Test Testington\n" +
                "nic-hdl:        TT01-AP\n" +
                "\n" +
                "% This query was served by the APNIC Whois Service version 0.1-TEST (UNDEFINED)\n" +
                "\n" +
                "\n", fullResponse);

        // Set limit to 3 query responses to local ip
        databaseHelper.insertAclIpLimit("127.0.0.1", -1, 3, true);
        ipResourceConfiguration.reload();
        ipTreeUpdater.rebuild();

        final String truncatedResponse = DummyWhoisClient.query(QueryServer.port, "-i mb MNT-USED-EVERYWHERE");
        assertNotNull(truncatedResponse);

        assertEquals("" +
                "% [whois.apnic.net]\n" +
                "% Whois data copyright terms    http://www.apnic.net/db/dbcopyright.html\n" +
                "\n" +
                "% Information related to '0.0.in-addr.arpa'\n" +
                "\n" +
                "domain:         0.0.in-addr.arpa\n" +
                "mnt-by:         MNT-USED-EVERYWHERE\n" +
                "admin-c:        TT01-AP\n" +
                "tech-c:         TT01-AP\n" +
                "\n" +
                "person:         Test Testington\n" +
                "nic-hdl:        TT01-AP\n" +
                "\n" +
                "% Information related to '0.1.in-addr.arpa'\n" +
                "\n" +
                "domain:         0.1.in-addr.arpa\n" +
                "mnt-by:         MNT-USED-EVERYWHERE\n" +
                "admin-c:        TT01-AP\n" +
                "tech-c:         TT01-AP\n" +
                "\n" +
                "%ERROR:201: access control limit reached for 127.0.0.1\n" +
                "%\n" +
                "% Too many objects in response; output has been truncated.\n" +
                "% For bulk access to WHOIS data, see http://www.apnic.net/whois/bulk-access\n" +
                "\n" +
                "% This query was served by the APNIC Whois Service version 0.1-TEST (UNDEFINED)\n" +
                "\n" +
                "\n", truncatedResponse);
    }


    @Test
    public void testAclQueryLimitsWithProxy() {
        // Setup data
        rpslObjectUpdateDao.createObject(RpslObject.parse("mntner: MNT-USED-EVERYWHERE"));
        rpslObjectUpdateDao.createObject(RpslObject.parse("person: Test Testington\nnic-hdl: TT01-AP"));
        for (int i = 0; i < 2; i++) {
            for (int j = 0; j < 2; j++) {
                rpslObjectUpdateDao.createObject(RpslObject.parse(String.format("domain: %d.%d.in-addr.arpa\n" +
                        "mnt-by: MNT-USED-EVERYWHERE\n" +
                        "admin-c: TT01-AP\ntech-c: TT01-AP", i, j)));
            }
        }

        // localhost to proxy ip's not set yet - fail
        ipResourceConfiguration.reload();
        ipTreeUpdater.rebuild();

        final String failResponseProxyIp = DummyWhoisClient.query(QueryServer.port, "-V testing,10.0.0.42  -i mb MNT-USED-EVERYWHERE");
        assertEquals("" +
                "% [whois.apnic.net]\n" +
                "% Whois data copyright terms    http://www.apnic.net/db/dbcopyright.html\n" +
                "\n" +
                "%ERROR:203: you are not allowed to act as a proxy\n" +
                "\n" +
                "% This query was served by the APNIC Whois Service version 0.1-TEST (UNDEFINED)\n" +
                "\n" +
                "\n", failResponseProxyIp);

        // Allow localhost to pass proxy ip
        databaseHelper.insertAclIpProxy("127.0.0.1");
        ipResourceConfiguration.reload();
        ipTreeUpdater.rebuild();

        final String fullResponseWithProxyIp = DummyWhoisClient.query(QueryServer.port, "--client testing,10.0.0.42  -i mb MNT-USED-EVERYWHERE");
        assertEquals("" +
                "% [whois.apnic.net]\n" +
                "% Whois data copyright terms    http://www.apnic.net/db/dbcopyright.html\n" +
                "\n" +
                "% Information related to '0.0.in-addr.arpa'\n" +
                "\n" +
                "domain:         0.0.in-addr.arpa\n" +
                "mnt-by:         MNT-USED-EVERYWHERE\n" +
                "admin-c:        TT01-AP\n" +
                "tech-c:         TT01-AP\n" +
                "\n" +
                "person:         Test Testington\n" +
                "nic-hdl:        TT01-AP\n" +
                "\n" +
                "% Information related to '0.1.in-addr.arpa'\n" +
                "\n" +
                "domain:         0.1.in-addr.arpa\n" +
                "mnt-by:         MNT-USED-EVERYWHERE\n" +
                "admin-c:        TT01-AP\n" +
                "tech-c:         TT01-AP\n" +
                "\n" +
                "person:         Test Testington\n" +
                "nic-hdl:        TT01-AP\n" +
                "\n" +
                "% Information related to '1.0.in-addr.arpa'\n" +
                "\n" +
                "domain:         1.0.in-addr.arpa\n" +
                "mnt-by:         MNT-USED-EVERYWHERE\n" +
                "admin-c:        TT01-AP\n" +
                "tech-c:         TT01-AP\n" +
                "\n" +
                "person:         Test Testington\n" +
                "nic-hdl:        TT01-AP\n" +
                "\n" +
                "% Information related to '1.1.in-addr.arpa'\n" +
                "\n" +
                "domain:         1.1.in-addr.arpa\n" +
                "mnt-by:         MNT-USED-EVERYWHERE\n" +
                "admin-c:        TT01-AP\n" +
                "tech-c:         TT01-AP\n" +
                "\n" +
                "person:         Test Testington\n" +
                "nic-hdl:        TT01-AP\n" +
                "\n" +
                "% This query was served by the APNIC Whois Service version 0.1-TEST (UNDEFINED)\n" +
                "\n" +
                "\n", fullResponseWithProxyIp);


        // Set limit to 3 query responses for proxied ip
        databaseHelper.insertAclIpLimit("10.0.0.42", -1, 3, true);
        ipResourceConfiguration.reload();
        ipTreeUpdater.rebuild();

        final String truncatedShortOptionResponse = DummyWhoisClient.query(QueryServer.port, "-V testing,10.0.0.42 -i mb MNT-USED-EVERYWHERE");
        assertEquals("" +
                "% [whois.apnic.net]\n" +
                "% Whois data copyright terms    http://www.apnic.net/db/dbcopyright.html\n" +
                "\n" +
                "% Information related to '0.0.in-addr.arpa'\n" +
                "\n" +
                "domain:         0.0.in-addr.arpa\n" +
                "mnt-by:         MNT-USED-EVERYWHERE\n" +
                "admin-c:        TT01-AP\n" +
                "tech-c:         TT01-AP\n" +
                "\n" +
                "person:         Test Testington\n" +
                "nic-hdl:        TT01-AP\n" +
                "\n" +
                "% Information related to '0.1.in-addr.arpa'\n" +
                "\n" +
                "domain:         0.1.in-addr.arpa\n" +
                "mnt-by:         MNT-USED-EVERYWHERE\n" +
                "admin-c:        TT01-AP\n" +
                "tech-c:         TT01-AP\n" +
                "\n" +
                "%ERROR:201: access control limit reached for 10.0.0.42\n" +
                "%\n" +
                "% Too many objects in response; output has been truncated.\n" +
                "% For bulk access to WHOIS data, see http://www.apnic.net/whois/bulk-access\n" +
                "\n" +
                "% This query was served by the APNIC Whois Service version 0.1-TEST (UNDEFINED)\n" +
                "\n" +
                "\n", truncatedShortOptionResponse);

        final String truncatedLongOptionResponse = DummyWhoisClient.query(QueryServer.port, "--client testing,10.0.0.42 -i mb MNT-USED-EVERYWHERE");
        assertEquals("" +
                "% [whois.apnic.net]\n" +
                "% Whois data copyright terms    http://www.apnic.net/db/dbcopyright.html\n" +
                "\n" +
                "% Information related to '0.0.in-addr.arpa'\n" +
                "\n" +
                "domain:         0.0.in-addr.arpa\n" +
                "mnt-by:         MNT-USED-EVERYWHERE\n" +
                "admin-c:        TT01-AP\n" +
                "tech-c:         TT01-AP\n" +
                "\n" +
                "person:         Test Testington\n" +
                "nic-hdl:        TT01-AP\n" +
                "\n" +
                "% Information related to '0.1.in-addr.arpa'\n" +
                "\n" +
                "domain:         0.1.in-addr.arpa\n" +
                "mnt-by:         MNT-USED-EVERYWHERE\n" +
                "admin-c:        TT01-AP\n" +
                "tech-c:         TT01-AP\n" +
                "\n" +
                "%ERROR:201: access control limit reached for 10.0.0.42\n" +
                "%\n" +
                "% Too many objects in response; output has been truncated.\n" +
                "% For bulk access to WHOIS data, see http://www.apnic.net/whois/bulk-access\n" +
                "\n" +
                "% This query was served by the APNIC Whois Service version 0.1-TEST (UNDEFINED)\n" +
                "\n" +
                "\n", truncatedLongOptionResponse);
    }
}
