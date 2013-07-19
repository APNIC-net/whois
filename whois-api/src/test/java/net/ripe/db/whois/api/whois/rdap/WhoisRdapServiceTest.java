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
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Response;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class WhoisRdapServiceTest {

    @Mock DateTimeProvider dateTimeProvider;
    @Mock UpdateRequestHandler updateRequestHandler;
    @Mock LoggerContext loggerContext;
    @Mock RpslObjectDao rpslObjectDao;
    @Mock QueryHandler queryHandler;
    @Mock HttpServletRequest request;

    @Mock SourceContext sourceContext;
    @Mock Source source;

    @InjectMocks WhoisRdapService subject;

    @Before
    public void setup() {
        when(sourceContext.getWhoisSlaveSource()).thenReturn(source);
        when(source.getName()).thenReturn(CIString.ciString("TEST"));
        when(sourceContext.getCurrentSource()).thenReturn(source);
        when(sourceContext.getAllSourceNames()).thenReturn(CIString.ciSet("TEST", "TEST-GRS"));
        when(request.getRemoteAddr()).thenReturn("127.0.0.1");
        when(request.getRequestURL()).thenReturn(new StringBuffer().append("127.0.0.1"));
    }

    @Test
    public void lookup_entity() {
        Response response = subject.lookup(request, "entity", "TP1-TEST");
    }
}
