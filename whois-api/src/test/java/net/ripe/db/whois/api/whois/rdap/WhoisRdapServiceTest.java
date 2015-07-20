package net.ripe.db.whois.api.whois.rdap;

import net.ripe.db.whois.common.DateTimeProvider;
import net.ripe.db.whois.common.dao.RpslObjectDao;
import net.ripe.db.whois.common.domain.CIString;
import net.ripe.db.whois.common.source.Source;
import net.ripe.db.whois.common.source.SourceContext;
import net.ripe.db.whois.query.handler.QueryHandler;
import net.ripe.db.whois.update.handler.UpdateRequestHandler;
import net.ripe.db.whois.update.log.LoggerContext;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class WhoisRdapServiceTest {

    @Mock DateTimeProvider dateTimeProvider;
    @Mock UpdateRequestHandler updateRequestHandler;
    @Mock LoggerContext loggerContext;
    @Mock RpslObjectDao rpslObjectDao;
    @Mock QueryHandler queryHandler;
    @Mock HttpServletRequest request;
    @Mock HttpHeaders httpHeaders;

    @Mock SourceContext sourceContext;
    @Mock Source source;

    //@InjectMocks
    WhoisRdapService subject;

    @Before
    public void setup() {
        when(sourceContext.getWhoisSlaveSource()).thenReturn(source);
        when(source.getName()).thenReturn(CIString.ciString("TEST"));
        when(sourceContext.getCurrentSource()).thenReturn(source);
        when(sourceContext.getAllSourceNames()).thenReturn(CIString.ciSet("TEST", "TEST-GRS"));
    }

    private void setupSubject() {
        setupSubject("http://localhost");
    }

    private void setupSubject(final String baseUrls) {
        subject = new WhoisRdapService(queryHandler, rpslObjectDao, null, null, null, null, null, "port43", baseUrls);
    }

    private void setupRequest() {
        setupRequest("http");
    }

    private void setupRequest(final String scheme) {
        when(request.getRemoteAddr()).thenReturn("127.0.0.1");
        when(request.getRequestURL()).thenReturn(new StringBuffer().append(scheme + "://localhost/"));
        when(request.getScheme()).thenReturn(scheme);
        when(request.getRequestURI()).thenReturn("/");
        when(request.getServletPath()).thenReturn("");
    }

    @Test
    public void lookup_entity() {
        setupSubject();
        setupRequest();
        final Response response = subject.lookup(request, httpHeaders, "entity", "TP1-TEST");
    }

    @Test
    public void get_base_url_identical_scheme() {
        // Check a request with http scheme uses a baseUrl of http://localhost
        // and a request with https scheme uses a baseUrl of https://localhost/rdap
        final String baseUrls = "http://localhost,https://localhost";
        setupSubject(baseUrls);
        final String[] schemes = {"http", "https"};
        for (String scheme : schemes) {
            setupRequest(scheme);
            assertThat("incorrect baseUrl generated", subject.getBaseUrl(request), is(scheme + "://localhost"));
        }
    }

    @Test
    public void get_base_url_unsupported_scheme() {
        // Check a request with http scheme uses a baseUrl of https://localhost/...
        // if http is not a preferred/supported scheme
        final String baseUrl = "https://localhost";
        setupSubject(baseUrl);
        final String scheme = "http";
        setupRequest(scheme);
        assertThat("incorrect baseUrl generated", subject.getBaseUrl(request), is(baseUrl));
    }

    @Test
    public void get_dynamic_base_url() {
        // Check that the base url is dynamically generated when no base url property is provided.
        setupSubject("");
        final String scheme = "http";
        setupRequest(scheme);
        assertThat("incorrect dynamic baseUrl generated", subject.getBaseUrl(request), is("http://localhost"));
    }
}
