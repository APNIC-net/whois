package net.ripe.db.whois.api.whois.rdap;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class RdapUrlFactoryTest {
    private static final String X_FORWARDED_PROTO_HEADER = "X-Forwarded-Proto";
    private static final String HELP_PATH = "/help";

    private static final String HTTP_LOCALHOST_RDAP = "http://localhost/rdap";
    private static final String HTTPS_LOCALHOST_RDAP = "https://localhost/rdap";

    @Mock private HttpServletRequest request;

    private RdapUrlFactory subject;


    @Test
    public void get_scheme_from_request_url() {
        when(request.getHeader(X_FORWARDED_PROTO_HEADER)).thenReturn(null);
        when(request.getScheme()).thenReturn("http");
        assertThat("incorrect scheme extracted from request", RdapUrlFactory.getScheme(request), is("http"));
    }

    @Test
    public void get_scheme_from_request_header() {
        when(request.getHeader(X_FORWARDED_PROTO_HEADER)).thenReturn("https");
        when(request.getScheme()).thenReturn("http");
        assertThat("incorrect scheme extracted from request", RdapUrlFactory.getScheme(request), is("https"));
    }

    @Test
    public void build_scheme_to_url_map() {
        Map<String, String> schemeToUrlMap;
        schemeToUrlMap = RdapUrlFactory.buildSchemeToUrlMap("");
        assertThat("empty string: returned null map", schemeToUrlMap, notNullValue());
        schemeToUrlMap = RdapUrlFactory.buildSchemeToUrlMap(HTTP_LOCALHOST_RDAP);
        assertThat("single entry: returned null map", schemeToUrlMap, notNullValue());
        assertThat("single entry: missing http entry", schemeToUrlMap.get("http"), is(HTTP_LOCALHOST_RDAP));
        schemeToUrlMap = RdapUrlFactory.buildSchemeToUrlMap(HTTP_LOCALHOST_RDAP + ',' +  HTTPS_LOCALHOST_RDAP);
        assertThat("multi entries: returned null map", schemeToUrlMap, notNullValue());
        assertThat("multi entries: missing http entry", schemeToUrlMap.get("http"), is(HTTP_LOCALHOST_RDAP));
        assertThat("multi entries: missing https entry", schemeToUrlMap.get("https"), is(HTTPS_LOCALHOST_RDAP));
    }

    @Test
    public void identical_scheme() {
        // Check a request with http scheme uses a baseUrl of http://localhost/rdap
        // and a request with https scheme uses a baseUrl of https://localhost/rdap
        final String requestPath = "/ip/1.2.3.0/24";
        when(request.getHeader(X_FORWARDED_PROTO_HEADER)).thenReturn(null);
        when(request.getPathInfo()).thenReturn(requestPath);
        when(request.getQueryString()).thenReturn("");

        final String[] schemes = {"http", "https"};
        for (String scheme : schemes) {
            when(request.getScheme()).thenReturn(scheme);
            subject = new RdapUrlFactory(request, RdapUrlFactory.buildSchemeToUrlMap(HTTP_LOCALHOST_RDAP + ',' + HTTPS_LOCALHOST_RDAP));
            assertThat("incorrect base url generated for scheme " + scheme, subject.getBaseUrl(), is(scheme + "://localhost/rdap"));
            assertThat("incorrect request url generated for scheme " + scheme, subject.getRequestUrl(), is(scheme + "://localhost/rdap" + requestPath));
            assertThat("incorrect object url generated for scheme " + scheme, subject.generateObjectUrl("ip", "1.2.3.4"), is(scheme + "://localhost/rdap/ip/1.2.3.4"));
            assertThat("incorrect help url generated for scheme " + scheme, subject.getHelpUrl(), is(scheme + "://localhost/rdap" + HELP_PATH));
        }
    }

    @Test
    public void unsupported_scheme() {
        // Check a request with http scheme uses a baseUrl of https://localhost/rdap
        // if http is not a preferred/supported scheme
        final String requestPath = "/ip/1.2.3.4";
        when(request.getHeader(X_FORWARDED_PROTO_HEADER)).thenReturn(null);
        when(request.getScheme()).thenReturn("http");
        when(request.getPathInfo()).thenReturn(requestPath);
        when(request.getQueryString()).thenReturn("");
        subject = new RdapUrlFactory(request, HTTPS_LOCALHOST_RDAP);

        assertThat("incorrect base url generated", subject.getBaseUrl(), is(HTTPS_LOCALHOST_RDAP));
        assertThat("incorrect request url generated", subject.getRequestUrl(), is(HTTPS_LOCALHOST_RDAP + requestPath));
        assertThat("incorrect object url generated", subject.generateObjectUrl("ip", "1.2.3.0/24"), is(HTTPS_LOCALHOST_RDAP + "/ip/1.2.3.0/24"));
        assertThat("incorrect help url generated", subject.getHelpUrl(), is(HTTPS_LOCALHOST_RDAP + HELP_PATH));
    }

    @Test
    public void dynamic_base_url() {
        // Check that the base url is dynamically generated when no base url property is provided.
        final String requestPath = "/ip/1.2.3.4";
        when(request.getHeader(X_FORWARDED_PROTO_HEADER)).thenReturn(null);
        when(request.getScheme()).thenReturn("http");
        when(request.getRequestURL()).thenReturn(new StringBuffer().append(HTTP_LOCALHOST_RDAP + requestPath));
        when(request.getRequestURI()).thenReturn("/rdap" + requestPath);
        when(request.getServletPath()).thenReturn("/rdap");
        when(request.getPathInfo()).thenReturn(requestPath);
        when(request.getQueryString()).thenReturn("");
        subject = new RdapUrlFactory(request);

        assertThat("incorrect base url generated", subject.getBaseUrl(), is(HTTP_LOCALHOST_RDAP));
        assertThat("incorrect request url generated", subject.getRequestUrl(), is(HTTP_LOCALHOST_RDAP + requestPath));
        assertThat("incorrect object url generated", subject.generateObjectUrl("ip", "1.2.3.0/24"), is(HTTP_LOCALHOST_RDAP + "/ip/1.2.3.0/24"));
        assertThat("incorrect help url generated", subject.getHelpUrl(), is(HTTP_LOCALHOST_RDAP + HELP_PATH));
    }
}
