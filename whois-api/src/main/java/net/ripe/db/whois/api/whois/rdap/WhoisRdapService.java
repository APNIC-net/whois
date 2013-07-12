package net.ripe.db.whois.api.whois.rdap;

import com.google.common.base.Function;
import com.google.common.base.Joiner;
import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import com.google.common.net.InetAddresses;
import net.ripe.db.whois.api.whois.ApiResponseHandler;
import net.ripe.db.whois.common.dao.VersionDao;
import net.ripe.db.whois.common.domain.ResponseObject;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.RpslObject;
import net.ripe.db.whois.common.source.SourceContext;
import net.ripe.db.whois.query.domain.QueryCompletionInfo;
import net.ripe.db.whois.query.domain.QueryException;
import net.ripe.db.whois.query.handler.QueryHandler;
import net.ripe.db.whois.query.planner.AbuseCFinder;
import net.ripe.db.whois.query.query.Query;
import net.ripe.db.whois.query.query.QueryFlag;
import org.codehaus.enunciate.modules.jersey.ExternallyManagedLifecycle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.net.InetAddress;
import java.util.List;
import java.util.Set;

import static net.ripe.db.whois.common.rpsl.ObjectType.*;

@ExternallyManagedLifecycle
@Component
@Path("/")
public class WhoisRdapService {
    private static final Logger LOGGER = LoggerFactory.getLogger(WhoisRdapService.class);

    private static final int STATUS_TOO_MANY_REQUESTS = 429;

    private final SourceContext sourceContext;
    private final QueryHandler queryHandler;
    private final VersionDao versionDao;
    private final AbuseCFinder abuseCFinder;
    private final String baseUrl;

    @Autowired
    public WhoisRdapService(final SourceContext sourceContext, final QueryHandler queryHandler, final VersionDao versionDao, final AbuseCFinder abuseCFinder, @Value("${rdap.public.baseUrl:}") final String baseUrl) {
        this.sourceContext = sourceContext;
        this.queryHandler = queryHandler;
        this.versionDao = versionDao;
        this.abuseCFinder = abuseCFinder;
        this.baseUrl = baseUrl;
    }

    @GET
    @Produces({MediaType.APPLICATION_JSON})
    @Path("/{objectType}/{key:.*}")
    public Response lookup(@Context final HttpServletRequest request,
                           @PathParam("objectType") final String objectType,
                           @PathParam("key") final String key) {

        final Set<ObjectType> whoisObjectTypes = Sets.newHashSet();

        switch (objectType) {
            case "autnum":
                whoisObjectTypes.add(AUT_NUM);
                break;

            case "domain":
                whoisObjectTypes.add(DOMAIN);
                break;

            case "ip":
                whoisObjectTypes.add(key.contains(":") ? INET6NUM : INETNUM);
                break;

            case "entity":
                whoisObjectTypes.add(PERSON);
                whoisObjectTypes.add(ROLE);
                // TODO: [RL] Configuration (property?) for allowed RPSL object types for entity lookups
                // TODO: [AS] Denis will look into if this should be used or not
                whoisObjectTypes.add(ORGANISATION);
                whoisObjectTypes.add(IRT);
                break;
        }

        Response response;

        if (!whoisObjectTypes.isEmpty()) {
            try {
                response = lookupObject(request, whoisObjectTypes, getKey(whoisObjectTypes, key));
            } catch (WebApplicationException webEx) {
                response = Response.status(webEx.getResponse().getStatus()).entity(RdapException.build(webEx.getResponse().getStatus())).build();
            }
        } else if (objectType.equals("nameserver")) {
            response = Response.status(Response.Status.NOT_FOUND).entity(RdapException.build(Response.Status.NOT_FOUND.getStatusCode())).build();
        } else {
            response = Response.status(Response.Status.BAD_REQUEST).entity(RdapException.build(Response.Status.BAD_REQUEST.getStatusCode())).build();
        }

        return response;
    }

    private String getKey(final Set<ObjectType> objectTypes, final String key) {
        if (objectTypes.contains(AUT_NUM)) {
            return String.format("AS%s", key);
        }
        return key;
    }

    protected Response lookupObject(final HttpServletRequest request, final Set<ObjectType> objectTypes, final String key) {
        final String source = sourceContext.getWhoisSlaveSource().getName().toString();
        final String objectTypesString = Joiner.on(",").join(Iterables.transform(objectTypes, new Function<ObjectType, String>() {
            @Override
            public String apply(final ObjectType input) {
                return input.getName();
            }
        }));

        final Query query = Query.parse(
                String.format("%s %s %s %s %s %s %s",
                        QueryFlag.NO_GROUPING.getLongFlag(),
                        // TODO: [RL] Configuration (property?) to control whether to fetch related objects?
                        // QueryFlag.NO_REFERENCED.getLongFlag(),
                        // TODO: [RL] Configure what sources to query? (APNIC will need additional sources)
                        QueryFlag.SOURCES.getLongFlag(),
                        source,
                        QueryFlag.SELECT_TYPES.getLongFlag(),
                        objectTypesString,
                        QueryFlag.NO_FILTERING.getLongFlag(),
                        key));

        return handleQuery(query, request);
    }

    protected Response handleQuery(final Query query, final HttpServletRequest request) {

        final int contextId = System.identityHashCode(Thread.currentThread());
        final InetAddress remoteAddress = InetAddresses.forString(request.getRemoteAddr());

        final List<RpslObject> result = Lists.newArrayList();

        try {
            queryHandler.streamResults(query, remoteAddress, contextId, new ApiResponseHandler() {
                @Override
                public void handle(final ResponseObject responseObject) {
                    if (responseObject instanceof RpslObject) {
                        result.add((RpslObject) responseObject);
                    }
                }
            });

            if (result.isEmpty()) {
                return Response.status(Response.Status.NOT_FOUND).build();
            }

            // The result size will be > 1 if we allow related objects
//            if (result.size() > 1) {
//                throw new IllegalStateException("Unexpected result size: " + result.size());
//            }

            final RpslObject resultObject = result.remove(0);

            return Response.ok(
                    RdapObjectMapper.map(
                        getRequestUrl(request),
                        getBaseUrl(request),
                        resultObject,
                        result,
                        // TODO: [RL] move these into RdapObjectMapper so that they can be used for nested objects?
                        versionDao.findByKey(resultObject.getType(), resultObject.getKey().toString()),
                        abuseCFinder.findAbuseContacts(resultObject))).build();

        } catch (final QueryException e) {
            if (e.getCompletionInfo() == QueryCompletionInfo.BLOCKED) {
                throw new WebApplicationException(Response.status(STATUS_TOO_MANY_REQUESTS).build());
            } else {
                LOGGER.error(e.getMessage(), e);
                throw e;
            }
        }
    }

    private String getBaseUrl(final HttpServletRequest request) {
        if (!this.baseUrl.isEmpty()) {
            return this.baseUrl;
        }

        final StringBuffer buffer = request.getRequestURL();
        buffer.setLength(buffer.length() - request.getRequestURI().length());

        return buffer.toString();
    }

    private String getRequestUrl(final HttpServletRequest request) {
        final StringBuffer buffer = request.getRequestURL();
        if (request.getQueryString() != null) {
            buffer.append('?');
            buffer.append(request.getQueryString());
        }
        return buffer.toString();
    }
}
