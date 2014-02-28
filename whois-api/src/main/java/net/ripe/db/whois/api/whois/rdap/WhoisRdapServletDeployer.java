package net.ripe.db.whois.api.whois.rdap;

import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import com.sun.jersey.spi.container.servlet.ServletContainer;
import net.ripe.db.whois.api.DefaultExceptionMapper;
import net.ripe.db.whois.api.httpserver.Audience;
import net.ripe.db.whois.api.httpserver.ServletDeployer;
import net.ripe.db.whois.api.whois.rdap.domain.Error;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.webapp.WebAppContext;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.handler.ErrorHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.annotation.*;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;
import java.util.Enumeration;
import java.util.Set;
import javax.ws.rs.core.Application;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Component
public class WhoisRdapServletDeployer implements ServletDeployer {

    private final WhoisRdapService whoisRDAPService;
    private final DefaultExceptionMapper defaultExceptionMapper;
    private final NoticeFactory noticeFactory;

    @Autowired
    public WhoisRdapServletDeployer(final WhoisRdapService whoisRDAPService, final DefaultExceptionMapper defaultExceptionMapper, final NoticeFactory noticeFactory) {
        this.whoisRDAPService = whoisRDAPService;
        this.defaultExceptionMapper = defaultExceptionMapper;
        this.noticeFactory = noticeFactory;
    }

    @Override
    public Audience getAudience() {
        return Audience.PUBLIC;
    }

    @Override
    public void deploy(final WebAppContext context) {
        final RdapJsonProvider rdapJsonProvider = new RdapJsonProvider();
        context.setErrorHandler(new ErrorHandler() {
            @Override
            public void handle(String target, Request baseRequest, HttpServletRequest request, HttpServletResponse response) throws IOException {
                String selfUrl = "";
                if (whoisRDAPService != null) {
                    selfUrl = whoisRDAPService.getBaseUrl(request);
                }
                if (request.getPathInfo() != null) {
                    selfUrl += request.getPathInfo();
                }
                if (request.getQueryString() != null) {
                    selfUrl += request.getQueryString();
                }
                if (!selfUrl.matches("/rdap/")) {
                    return;
                }

                Enumeration<String> acceptHeaders = request.getHeaders("Accept");
                List<MediaType> mediaTypes = new ArrayList<MediaType>();
                while (acceptHeaders.hasMoreElements()) {
                    try {
                        String acceptHeader = acceptHeaders.nextElement();
                        List<String> acceptComponents = Arrays.asList(acceptHeader.split(","));
                        for (String acceptComponent: acceptComponents) {
                            mediaTypes.add(MediaType.valueOf(acceptComponent));
                        }
                    } catch (Exception e) {
                    }
                }
                
                String mediaType = whoisRDAPService.getAcceptableMediaType(mediaTypes);
                if (mediaType == null) {
                    mediaType = RdapJsonProvider.CONTENT_TYPE_RDAP_JSON;
                    response.setStatus(406);
                }
                response.setCharacterEncoding("utf-8");

                response.setHeader("Content-Type", mediaType);
                response.setHeader("Access-Control-Allow-Origin", "*");

                Error rdapError = (Error) RdapException.build(Response.Status.fromStatusCode(response.getStatus()), selfUrl, noticeFactory);
                ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                rdapJsonProvider.writeTo((Object) rdapError, rdapError.getClass(), rdapError.getClass(), new Annotation[0], null, null, byteArrayOutputStream);
                String responseContent = byteArrayOutputStream.toString();
                response.getWriter().write(responseContent); 
            }
        });
        context.addServlet(new ServletHolder("Whois RDAP REST API", new ServletContainer(new Application() {
            @Override
            public Set<Object> getSingletons() {
                return Sets.newLinkedHashSet(Lists.<Object>newArrayList(
                        whoisRDAPService,
                        defaultExceptionMapper,
                        rdapJsonProvider));
            }
        })), "/rdap/*");
    }
}
