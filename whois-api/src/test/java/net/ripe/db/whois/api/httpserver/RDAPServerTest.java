package net.ripe.db.whois.api.httpserver;

import net.ripe.db.whois.api.AbstractRestClientTest;
import net.ripe.db.whois.common.IntegrationTest;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import java.net.HttpURLConnection;
import java.net.URL;

import static org.junit.Assert.assertEquals;

@Category(IntegrationTest.class)
public class RDAPServerTest extends AbstractRestClientTest {
    private static final Audience RDAP_AUDIENCE = Audience.RDAP;

    @Test
    public void rdapServerTest() throws Exception {
        int rdapPort = getPort(RDAP_AUDIENCE);
        URL url = new URL("http://localhost:" + rdapPort + "/index.html");
        HttpURLConnection httpConnect = (HttpURLConnection)url.openConnection();
        httpConnect.connect();
        // @TODO: This guy is busted, fix me Andy!!!
        assertEquals(404, httpConnect.getResponseCode());
        httpConnect.disconnect();
    }
}
