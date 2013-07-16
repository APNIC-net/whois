package net.ripe.db.whois.api.whois.rdap;

import com.google.common.base.Function;
import com.google.common.base.Joiner;
import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import com.google.common.net.InetAddresses;
import net.ripe.db.whois.api.whois.ApiResponseHandler;
import net.ripe.db.whois.common.dao.RpslObjectDao;
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
import java.util.Collections;
import java.util.List;
import java.util.Set;

import static net.ripe.db.whois.common.rpsl.ObjectType.*;

@ExternallyManagedLifecycle
@Component
@Path("/")
public class WhoisRdapService {
    private static final Logger LOGGER = LoggerFactory.getLogger(WhoisRdapService.class);
    private static final int STATUS_TOO_MANY_REQUESTS = 429;
    private static final Set<ObjectType> ABUSE_CONTACT_TYPES = Sets.newHashSet(AUT_NUM, INETNUM, INET6NUM);

    private final SourceContext sourceContext;
    private final QueryHandler queryHandler;
    private final RpslObjectDao objectDao;
    private final AbuseCFinder abuseCFinder;
    private final String baseUrl;

    @Autowired
    public WhoisRdapService(final SourceContext sourceContext, final QueryHandler queryHandler, final RpslObjectDao objectDao, final AbuseCFinder abuseCFinder, @Value("${rdap.public.baseUrl:}") final String baseUrl) {
        this.sourceContext = sourceContext;
        this.queryHandler = queryHandler;
        this.objectDao = objectDao;
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
                whoisObjectTypes.add(
                    objectExists(request, AUT_NUM, "AS" + key)
                        ? AUT_NUM
                        : AS_BLOCK
                );
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
                int statusCode = webEx.getResponse().getStatus();
                response = Response.status(statusCode).entity(RdapException.build(Response.Status.fromStatusCode(statusCode))).build();
            }
        } else if (objectType.equals("nameserver")) {
            response = Response.status(Response.Status.NOT_FOUND).entity(RdapException.build(Response.Status.NOT_FOUND)).build();
        } else {
            response = Response.status(Response.Status.BAD_REQUEST).entity(RdapException.build(Response.Status.BAD_REQUEST)).build();
        }

        return response;
    }

    private String getKey(final Set<ObjectType> objectTypes, final String key) {
        if (objectTypes.contains(AUT_NUM) || objectTypes.contains(AS_BLOCK)) {
            return String.format("AS%s", key);
        }
        return key;
    }

    protected Response lookupObject(final HttpServletRequest request, final Set<ObjectType> objectTypes, final String key) {
        final String objectTypesString = Joiner.on(",").join(Iterables.transform(objectTypes, new Function<ObjectType, String>() {
            @Override
            public String apply(final ObjectType input) {
                return input.getName();
            }
        }));

        final Query query = Query.parse(
                String.format("%s %s %s %s %s",
                        QueryFlag.NO_GROUPING.getLongFlag(),
                        QueryFlag.SELECT_TYPES.getLongFlag(),
                        objectTypesString,
                        QueryFlag.NO_FILTERING.getLongFlag(),
                        key));

        return handleQuery(query, request);
    }

    protected boolean objectExists(final HttpServletRequest request, final ObjectType objectType, final String key) {
        final int contextId = System.identityHashCode(Thread.currentThread());
        final InetAddress localAddress;
        try {
            localAddress = InetAddress.getLocalHost();
        } catch (Exception e) {
            throw new WebApplicationException(Response.status(Response.Status.INTERNAL_SERVER_ERROR).build());
        }

        final List<RpslObject> result = Lists.newArrayList();

        final Query query = Query.parse(
                String.format("%s %s %s %s %s",
                        QueryFlag.NO_GROUPING.getLongFlag(),
                        QueryFlag.SELECT_TYPES.getLongFlag(),
                        objectType.getName(),
                        QueryFlag.NO_FILTERING.getLongFlag(),
                        key));

        try {
            queryHandler.streamResults(query, localAddress, contextId, new ApiResponseHandler() {
                @Override
                public void handle(final ResponseObject responseObject) {
                    if (responseObject instanceof RpslObject) {
                        result.add((RpslObject) responseObject);
                    }
                }
            });
        } catch (Exception e) {
            throw new WebApplicationException(Response.status(Response.Status.INTERNAL_SERVER_ERROR).build());
        }

        return !result.isEmpty();
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
                throw new WebApplicationException(Response.status(Response.Status.NOT_FOUND).build());
            }

//            The result size will be > 1 when we allow related objects
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
                            // TODO: [RL] move these two params into methods on RdapObjectMapper so that they can be used for nested objects?
                            objectDao.getLastUpdated(resultObject.getObjectId()),
                            // TODO: [RL] for the equivalent, APNIC needs to find the referenced IRT object
                            getAbuseContacts(resultObject))).build();

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
        buffer.setLength(buffer.length() - request.getRequestURI().length() + request.getServletPath().length());

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

    private List<RpslObject> getAbuseContacts(final RpslObject rpslObject) {
        final ObjectType objectType = rpslObject.getType();
        if (ABUSE_CONTACT_TYPES.contains(objectType)) {
            return abuseCFinder.findAbuseContacts(rpslObject);
        }
        return Collections.emptyList();
    }
}