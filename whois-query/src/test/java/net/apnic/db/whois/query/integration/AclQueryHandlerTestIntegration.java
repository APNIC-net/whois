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

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

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
        assertTrue(fullResponse.contains("" +
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
                "% This query was served by the APNIC Whois Service version 0.1-TEST (UNDEFINED)\n"));

        // Set limit to 3 query responses for another ip
        databaseHelper.insertAclIpLimit("111.112.113.114", -1, 3, true);
        ipResourceConfiguration.reload();
        ipTreeUpdater.rebuild();

        final String fullResponseDifferentIp = DummyWhoisClient.query(QueryServer.port, "-i mb MNT-USED-EVERYWHERE");
        assertTrue(fullResponseDifferentIp.contains("" +
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
                "% This query was served by the APNIC Whois Service version 0.1-TEST (UNDEFINED)\n"));


        // Set limit to 3 query responses to local ip
        databaseHelper.insertAclIpLimit("127.0.0.1", -1, 3, true);
        ipResourceConfiguration.reload();
        ipTreeUpdater.rebuild();

        final String truncatedResponse = DummyWhoisClient.query(QueryServer.port, "-i mb MNT-USED-EVERYWHERE");
        assertNotNull(truncatedResponse);


        assertTrue(truncatedResponse.contains("" +
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
                "% For bulk access to WHOIS data, see http://www.apnic.net/whois/bulk-access\n"));
    }
}
