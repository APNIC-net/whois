package net.ripe.db.whois.api.whois.rdap;

import net.ripe.db.whois.common.domain.CIString;
import net.ripe.db.whois.common.grs.AuthoritativeResource;
import net.ripe.db.whois.common.grs.AuthoritativeResourceData;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.query.query.Query;
import org.apache.commons.lang.StringUtils;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.util.StringValueResolver;

import java.net.URI;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class DelegatedStatsServiceTest {

    private static final String BANANA_GRS = "BANANA-GRS";
    private static final String DEFAULT_REQUEST_PATH = "/ip/2001:67c:2e8:22::c100:68b";
    private static final Query DEFAULT_QUERY = Query.parse("--no-grouping --select-types inet6num --no-filtering 2001:67c:2e8:22::c100:68b");
    private static final String BANANA_GRS_BASEURL = "://banana.net/rdap";

    @Mock
    private AuthoritativeResourceData authoritativeResourceData;
    @Mock
    private AuthoritativeResource authoritativeResource;
    @Mock
    private StringValueResolver valueResolver;

    private DelegatedStatsService subject;


    @Before
    public void setup() {
        when(authoritativeResourceData.getAuthoritativeResource(CIString.ciString(BANANA_GRS))).thenReturn(authoritativeResource);
        when(authoritativeResource.isMaintainedInRirSpace(any(ObjectType.class), any(CIString.class))).thenReturn(true);
    }

    private void setupSourcePaths(final String... sourcePaths) {
        when(valueResolver.resolveStringValue(
                String.format("${rdap.redirect.%s:}", BANANA_GRS.toLowerCase().replace("-grs", ""))
            )).thenReturn(StringUtils.join(sourcePaths, ','));

        subject = new DelegatedStatsService(BANANA_GRS, authoritativeResourceData);
        subject.setEmbeddedValueResolver(valueResolver);
        subject.init();
    }

    @Test
    public void redirect_using_identical_scheme() {
        // Check http redirects to http://banana.net/rdap/... and https redirects to https://banana.net/rdap/...
        final String[] schemes = new String[] {"http", "https"};
        setupSourcePaths(schemes[0] + BANANA_GRS_BASEURL, schemes[1] + BANANA_GRS_BASEURL);
        for (String scheme : schemes) {
            final URI redirectUri = subject.getUriForRedirect(scheme, DEFAULT_REQUEST_PATH, DEFAULT_QUERY);
            assertThat("generated redirectUri is wrong when using scheme: " + scheme,
                    redirectUri.toString(), is(scheme + BANANA_GRS_BASEURL + DEFAULT_REQUEST_PATH));
        }
    }

    @Test
    public void redirect_from_unsupported_scheme() {
        // Check http redirects to https://banana.net/rdap/... when http scheme is not supported
        setupSourcePaths("https" + BANANA_GRS_BASEURL);
        final URI redirectUri = subject.getUriForRedirect("http", DEFAULT_REQUEST_PATH, DEFAULT_QUERY);
        assertThat("generated redirectUri is wrong", redirectUri.toString(),
                is("https" + BANANA_GRS_BASEURL + DEFAULT_REQUEST_PATH));
    }
}
