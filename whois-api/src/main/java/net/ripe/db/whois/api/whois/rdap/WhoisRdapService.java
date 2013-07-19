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
import net.ripe.db.whois.common.domain.attrs.AttributeParseException;
import net.ripe.db.whois.common.domain.attrs.Domain;
import net.ripe.db.whois.common.rpsl.AttributeType;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.RpslObject;
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

import static net.ripe.db.whois.common.rpsl.ObjectType.AS_BLOCK;
import static net.ripe.db.whois.common.rpsl.ObjectType.AUT_NUM;
import static net.ripe.db.whois.common.rpsl.ObjectType.DOMAIN;
import static net.ripe.db.whois.common.rpsl.ObjectType.INET6NUM;
import static net.ripe.db.whois.common.rpsl.ObjectType.INETNUM;
import static net.ripe.db.whois.common.rpsl.ObjectType.IRT;
import static net.ripe.db.whois.common.rpsl.ObjectType.ORGANISATION;
import static net.ripe.db.whois.common.rpsl.ObjectType.PERSON;
import static net.ripe.db.whois.common.rpsl.ObjectType.ROLE;

@ExternallyManagedLifecycle
@Component
@Path("/")
public class WhoisRdapService {
    private static final Logger LOGGER = LoggerFactory.getLogger(WhoisRdapService.class);
    private static final int STATUS_TOO_MANY_REQUESTS = 429;
    private static final Set<ObjectType> ABUSE_CONTACT_TYPES = Sets.newHashSet(AUT_NUM, INETNUM, INET6NUM);


    private final QueryHandler queryHandler;
    private final RpslObjectDao objectDao;
    private final AbuseCFinder abuseCFinder;
    private final String baseUrl;

    @Autowired
    public WhoisRdapService(final QueryHandler queryHandler, final RpslObjectDao objectDao, final AbuseCFinder abuseCFinder, @Value("${rdap.public.baseurl:}") final String baseUrl) {
        this.queryHandler = queryHandler;
        this.objectDao = objectDao;
        this.abuseCFinder = abuseCFinder;
        this.baseUrl = baseUrl;
    }

    @GET
    @Produces({RdapJsonProvider.CONTENT_TYPE_RDAP_JSON, MediaType.APPLICATION_JSON})
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
                validateDomain(key);
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

        String selfUrl = request.getRequestURL().toString();

        if (!whoisObjectTypes.isEmpty()) {
            try {
                response = lookupObject(request, whoisObjectTypes, getKey(whoisObjectTypes, key));
            } catch (WebApplicationException webEx) {
                int statusCode = webEx.getResponse().getStatus();
                response = Response.status(statusCode).entity(RdapException.build(Response.Status.fromStatusCode(statusCode),selfUrl)).build();
            }
        } else if (objectType.equals("nameserver")) {
            response = Response.status(Response.Status.NOT_FOUND).entity(RdapException.build(Response.Status.NOT_FOUND,selfUrl)).build();
        } else {
            response = Response.status(Response.Status.BAD_REQUEST).entity(RdapException.build(Response.Status.BAD_REQUEST,selfUrl)).build();
        }

        return response;
    }

    @GET
    @Produces({MediaType.APPLICATION_JSON, RdapJsonProvider.CONTENT_TYPE_RDAP_JSON})
    @Path("/help")
    public Response lookupHelp(@Context final HttpServletRequest request) {
        Response response;
        String selfUrl = request.getRequestURL().toString();
        response = Response.ok().entity(RdapHelp.build(selfUrl)).build();
        return response;
    }

    private void validateDomain(final String key) {
        try {
            Domain.parse(key);
        } catch (AttributeParseException e) {
            throw new IllegalArgumentException("RIPE NCC does not support forward domain queries.");
        }
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
        return handleQuery(getLookupQuery(objectTypesString, key), request);
    }

    private boolean objectExists(final HttpServletRequest request, final ObjectType objectType, final String key) {
        final Query query = getLookupQuery(objectType.getName(), key);
        final List<RpslObject> result = runQuery(query, request, true);
        return !result.isEmpty();
    }

    protected Response handleQuery(final Query query, final HttpServletRequest request) {
        try {
            final List<RpslObject> result = runQuery(query, request, false);
            if (result.isEmpty()) {
                throw new WebApplicationException(Response.status(Response.Status.NOT_FOUND).build());
            }

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
                            getMntIrt(resultObject),
                            getParentObject(resultObject))).build();

        } catch (final QueryException e) {
            if (e.getCompletionInfo() == QueryCompletionInfo.BLOCKED) {
                throw new WebApplicationException(Response.status(STATUS_TOO_MANY_REQUESTS).build());
            } else {
                System.out.println(e.toString());
                LOGGER.error(e.getMessage(), e);
                throw e;
            }
        }
    }

    private List<RpslObject> runQuery(final Query query, final HttpServletRequest request, final boolean internalRequest) {
        final int contextId = System.identityHashCode(Thread.currentThread());
        final InetAddress queryAddress;
        if (internalRequest) {
            try {
                queryAddress = InetAddress.getLocalHost();
            } catch (Exception e) {
                throw new WebApplicationException(Response.status(Response.Status.INTERNAL_SERVER_ERROR).build());
            }
        } else {
            queryAddress = InetAddresses.forString(request.getRemoteAddr());
        }

        final List<RpslObject> result = Lists.newArrayList();

        try {
            queryHandler.streamResults(query, queryAddress, contextId, new ApiResponseHandler() {
                @Override
                public void handle(final ResponseObject responseObject) {
                    if (responseObject instanceof RpslObject) {
                        result.add((RpslObject) responseObject);
                    }
                }
            });

        } catch (final QueryException e) {
            if (e.getCompletionInfo() == QueryCompletionInfo.BLOCKED) {
                throw new WebApplicationException(Response.status(STATUS_TOO_MANY_REQUESTS).build());
            } else {
                LOGGER.error(e.getMessage(), e);
                throw e;
            }
        }

        return result;
    }

    private String getBaseUrl(final HttpServletRequest request) {
        if (!this.baseUrl.isEmpty()) {
            return this.baseUrl;
        }

        final StringBuffer buffer = request.getRequestURL();
        buffer.setLength(buffer.length() - request.getRequestURI().length() + request.getServletPath().length());

        return buffer.toString();
    }

    private Query getLookupQuery(final String objectType, final String key) {
        return Query.parse(
                String.format("%s %s %s %s %s",
                        QueryFlag.NO_GROUPING.getLongFlag(),
                        QueryFlag.SELECT_TYPES.getLongFlag(),
                        objectType,
                        QueryFlag.NO_FILTERING.getLongFlag(),
                        key));
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

    private List<RpslObject> getMntIrt(final RpslObject rpslObject) {
        if (rpslObject.containsAttribute(AttributeType.MNT_IRT)) {
            final String queryString = String.format("%s %s %s %s %s",
                    QueryFlag.NO_GROUPING.getLongFlag(),
                    QueryFlag.SELECT_TYPES.getLongFlag(),
                    IRT,
                    QueryFlag.NO_FILTERING.getLongFlag(),
                    rpslObject.getValueForAttribute(AttributeType.MNT_IRT).toString());
            final Query query = Query.parse(
                    queryString);
            return runQuery(
                    query,
                    null,
                    true
            );
        }

        return Collections.emptyList();
    }

    private RpslObject getParentObject(final RpslObject rpslObject) {
        final ObjectType objectType = rpslObject.getType();
        if ((objectType == INETNUM) || (objectType == INET6NUM)) {
            final List<RpslObject> parents = runQuery(
                Query.parse(
                        String.format("%s %s %s %s %s %s",
                                QueryFlag.NO_GROUPING.getLongFlag(),
                                QueryFlag.SELECT_TYPES.getLongFlag(),
                                objectType,
                                QueryFlag.NO_FILTERING.getLongFlag(),
                                QueryFlag.ONE_LESS.getLongFlag(),
                                rpslObject.getKey().toString())),
                null,
                true
            );
            if (parents.size() > 0) {
                return parents.get(0);
            }
        }
        return null;
    }
}
