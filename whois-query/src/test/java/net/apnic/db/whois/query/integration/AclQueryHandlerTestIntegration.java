package net.apnic.db.whois.query.integration;

import net.ripe.db.whois.common.IntegrationTest;
import net.ripe.db.whois.common.rpsl.RpslObject;
import net.ripe.db.whois.common.support.DummyWhoisClient;
import net.ripe.db.whois.query.QueryServer;
import net.ripe.db.whois.query.support.AbstractWhoisIntegrationTest;
import org.junit.After;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.Assert.assertNotNull;

@Category(IntegrationTest.class)
public class AclQueryHandlerTestIntegration extends AbstractWhoisIntegrationTest {
    private static final Logger LOGGER = LoggerFactory.getLogger(AclQueryHandlerTestIntegration.class);

    @After
    public void teardown() {
        queryServer.stop(true);
    }

    @Test
    public void testAcl() {
        LOGGER.info("Stopping query server");
        queryServer.stop(true);

        databaseHelper.insertAclIpLimit("127.0.0.1", -1, 5, true);
        rpslObjectUpdateDao.createObject(RpslObject.parse("mntner: MNT-USED-EVERYWHERE"));
        rpslObjectUpdateDao.createObject(RpslObject.parse("person: Test Testington\nnic-hdl: TT01-AP"));
        for (int i = 0; i < 2; i++) {
            for (int j = 0; j < 20; j++) {
                rpslObjectUpdateDao.createObject(RpslObject.parse(String.format("domain: %d.%d.in-addr.arpa\n" +
                        "mnt-by: MNT-USED-EVERYWHERE\n" +
                        "admin-c: TT01-AP\ntech-c: TT01-AP", i, j)));
            }
        }
        ipResourceConfiguration.reload();
        ipTreeUpdater.rebuild();

        LOGGER.info("Restarting query server");
        queryServer.start();

        final String response = DummyWhoisClient.query(QueryServer.port, "-i mb MNT-USED-EVERYWHERE");
        assertNotNull(response);
        LOGGER.info("response=" + response);
        System.out.println("response=" + response);
    }
}
