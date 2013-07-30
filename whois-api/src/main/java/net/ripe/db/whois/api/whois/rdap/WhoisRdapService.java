package net.ripe.db.whois.api.whois.rdap;

import com.google.common.base.Function;
import com.google.common.base.Joiner;
import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import com.google.common.net.InetAddresses;
import net.ripe.db.whois.api.whois.ApiResponseHandler;
import net.ripe.db.whois.api.whois.rdap.domain.RdapObject;
import net.ripe.db.whois.common.dao.RpslObjectDao;
import net.ripe.db.whois.common.domain.IpInterval;
import net.ripe.db.whois.common.domain.ResponseObject;
import net.ripe.db.whois.common.domain.attrs.AttributeParseException;
import net.ripe.db.whois.common.domain.attrs.AutNum;
import net.ripe.db.whois.common.domain.attrs.Domain;
import net.ripe.db.whois.common.rpsl.AttributeType;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.RpslAttribute;
import net.ripe.db.whois.common.rpsl.RpslObject;
import net.ripe.db.whois.query.domain.QueryCompletionInfo;
import net.ripe.db.whois.query.domain.QueryException;
import net.ripe.db.whois.query.handler.QueryHandler;
import net.ripe.db.whois.query.planner.AbuseCFinder;
import net.ripe.db.whois.query.query.Query;
import net.ripe.db.whois.query.query.QueryFlag;
import org.apache.commons.lang.StringUtils;
import org.codehaus.enunciate.modules.jersey.ExternallyManagedLifecycle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.net.InetAddress;
import java.net.URI;
import java.util.Collections;
import java.util.List;
import java.util.Properties;
import java.util.Set;

import static net.ripe.db.whois.common.rpsl.ObjectType.*;

@ExternallyManagedLifecycle
@Component
@Path("/")
public class WhoisRdapService {
    private static final Logger LOGGER = LoggerFactory.getLogger(WhoisRdapService.class);

    private static final int STATUS_TOO_MANY_REQUESTS = 429;
    private static final Set<ObjectType> ABUSE_CONTACT_TYPES = Sets.newHashSet(AUT_NUM, INETNUM, INET6NUM);

    private static final Joiner SLASH_JOINER = Joiner.on("/");
    public static final Joiner COMMA_JOINER = Joiner.on(",");

    protected static Properties properties = new Properties();
    protected static String rdapPropertiesPath = System.getProperty("rdap.config","");

    static {
        if (rdapPropertiesPath.equals("")) {
            rdapPropertiesPath = "classpath:rdap.properties";
        } else {
            rdapPropertiesPath = "file:" + rdapPropertiesPath;
        }
        try {
            ApplicationContext appContext = new ClassPathXmlApplicationContext();
            Resource resource = appContext.getResource(rdapPropertiesPath);
            LOGGER.info(String.format("Loading [%s] from [%s]",rdapPropertiesPath, resource.getURL().toExternalForm()));
            properties.load(resource.getInputStream());
        } catch (IOException ioex) {
            String error = String.format("Failed to load properties file [%s]", rdapPropertiesPath);
            LOGGER.error(error);
            throw new ExceptionInInitializerError(error);
        }
    }

    private final QueryHandler queryHandler;
    private final RpslObjectDao objectDao;
    private final AbuseCFinder abuseCFinder;
    private final String baseUrl;

    private String port43 = (String)properties.get("rdap.port43");

    @Autowired
    public WhoisRdapService(final QueryHandler queryHandler, final RpslObjectDao objectDao, final AbuseCFinder abuseCFinder) {
        this(queryHandler,objectDao, abuseCFinder, null);
    }

    public WhoisRdapService(final QueryHandler queryHandler, final RpslObjectDao objectDao, final AbuseCFinder abuseCFinder, final String baseUrl) {
        this.queryHandler = queryHandler;
        this.objectDao = objectDao;
        this.abuseCFinder = abuseCFinder;
        if (StringUtils.isEmpty(baseUrl)) {
            this.baseUrl = (String)properties.get("rdap.public.baseurl");
        } else {
            this.baseUrl = baseUrl;
        }
    }

    @GET
    @Produces( { RdapJsonProvider.CONTENT_TYPE_RDAP_JSON, MediaType.APPLICATION_JSON, MediaType.TEXT_PLAIN})
    @Path("/{objectType}/{key:.*}")
    public Response lookup(@Context final HttpServletRequest request,
                           @Context HttpHeaders httpHeaders,
                           @PathParam("objectType") final String objectType,
                           @PathParam("key") final String key) {

        Response.ResponseBuilder response;
        String selfUrl = SLASH_JOINER.join(getBaseUrl(request), objectType, key);

        final Set<ObjectType> whoisObjectTypes = Sets.newHashSet();
        try {
            switch (objectType.toLowerCase()) {
                case "autnum":
                    validateAutnum("AS" + key);
                    whoisObjectTypes.add(objectExists(request, AUT_NUM, "AS" + key) ? AUT_NUM : AS_BLOCK);
                    break;

                case "domain":
                    validateDomain(key);
                    whoisObjectTypes.add(DOMAIN);
                    break;

                case "ip":
                    validateIp(key);
                    whoisObjectTypes.add(key.contains(":") ? INET6NUM : INETNUM);
                    break;

                case "entity":
                    validateEntity(key);
                    // TODO: [RL] Configuration (property?) for allowed RPSL object types for entity lookups
                    if (key.toUpperCase().startsWith("IRT-")) {
                        whoisObjectTypes.add(IRT);
                    } else if (key.toUpperCase().startsWith("ORG-")) {
                        whoisObjectTypes.add(ORGANISATION);
                    } else {
                        whoisObjectTypes.add(PERSON);
                        whoisObjectTypes.add(ROLE);
                    }
                    break;

                case "nameserver" : break; // Not yet supported
            }

            if (whoisObjectTypes.isEmpty()) {
                throw new WebApplicationException(Response.Status.BAD_REQUEST);
            }

            response = Response.ok(lookupObject(request, whoisObjectTypes, getKey(whoisObjectTypes, key)));

        } catch (WebApplicationException webex) {
            LOGGER.error("RDAP error", webex);
            int statusCode = webex.getResponse().getStatus();
            response = Response.status(statusCode).entity(RdapException.build(Response.Status.fromStatusCode(statusCode), selfUrl));
        } catch (IllegalArgumentException iae) {
            response = Response.status(Response.Status.BAD_REQUEST.getStatusCode()).entity(RdapException.build(Response.Status.BAD_REQUEST, selfUrl));
        } catch (Throwable t) {
            LOGGER.error("RDAP Internal Server error", t);
            // catch Everything
            response = Response.status(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode()).entity(RdapException.build(Response.Status.INTERNAL_SERVER_ERROR, selfUrl));
        }
        mapAcceptableMediaType(response, httpHeaders.getAcceptableMediaTypes());
        response.header("Access-Control-Allow-Origin", "*");
        return response.build();
    }

    @GET
    @Produces( { RdapJsonProvider.CONTENT_TYPE_RDAP_JSON, MediaType.APPLICATION_JSON, MediaType.TEXT_PLAIN})
    @Path("/help")
    public Response lookupHelp(@Context final HttpServletRequest request, @Context HttpHeaders httpHeaders) {
        final String selfUrl =  getBaseUrl(request) + "/help";
        final Response.ResponseBuilder response = Response.ok().entity(RdapHelp.build(selfUrl));
        mapAcceptableMediaType(response, httpHeaders.getAcceptableMediaTypes());
        response.header("Access-Control-Allow-Origin", "*");
        return response.build();
    }

    @GET
    @Path("/")
    public Response redirectToDocumentation(@Context final HttpServletRequest request) {
        return Response.status(Response.Status.MOVED_PERMANENTLY).location(URI.create(getBaseUrl(request) + "/help")).build();
    }


    private void validateDomain(final String key) {
        try {
            Domain.parse(key);
        } catch (AttributeParseException e) {
            throw new IllegalArgumentException("Invalid syntax.");
        }
    }

    private void validateIp(final String key) {
        try {
            IpInterval.parse(key);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid syntax.", e);
        }
    }

    private void validateAutnum(final String key) {
        try {
            AutNum.parse(key);
        } catch (AttributeParseException e) {
            throw new IllegalArgumentException("Invalid syntax.", e);
        }
    }

    private void validateEntity(final String key) {
        if (key.toUpperCase().startsWith("ORG-")) {
            if (!AttributeType.ORGANISATION.isValidValue(ORGANISATION, key)) {
                throw new IllegalArgumentException("Invalid syntax.");
            }
        } else if (key.toUpperCase().startsWith("IRT-")) {
            if (!AttributeType.IRT.isValidValue(IRT, key)) {
                throw new IllegalArgumentException("Invalid syntax.");
            }
        } else {
            if (!AttributeType.NIC_HDL.isValidValue(ObjectType.PERSON, key)) {
                throw new IllegalArgumentException("Invalid syntax");
            }
        }
    }

    private String getKey(final Set<ObjectType> objectTypes, final String key) {
        if (objectTypes.contains(AUT_NUM) || objectTypes.contains(AS_BLOCK)) {
            return String.format("AS%s", key);
        }
        return key;
    }

    protected RdapObject lookupObject(final HttpServletRequest request, final Set<ObjectType> objectTypes, final String key) {
        final String objectTypesString = COMMA_JOINER.join(Iterables.transform(objectTypes, new Function<ObjectType, String>() {
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

    protected RdapObject handleQuery(final Query query, final HttpServletRequest request) {
        try {
            final List<RpslObject> result = runQuery(query, request, false);
            if (result.isEmpty()) {
                throw new WebApplicationException(Response.status(Response.Status.NOT_FOUND).build());
            }

            final RpslObject resultObject = result.remove(0);

            List<RpslObject> abuseContacts = Lists.newArrayList();
//            abuseContacts.addAll(getAbuseContacts(resultObject));
            abuseContacts.addAll(getMntIrt(resultObject));
            return RdapObjectMapper.map(
                    getRequestUrl(request),
                    getBaseUrl(request),
                    resultObject,
                    result,
                    // TODO: [RL] move these two params into methods on RdapObjectMapper so that they can be used for nested objects?
                    objectDao.getLastUpdated(resultObject.getObjectId()),
                    // TODO: [RL] for the equivalent, APNIC needs to find the referenced IRT object
                    abuseContacts,
                    getParentObject(resultObject),
                    port43);

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

    protected static Properties getProperties() {
        return properties;
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
        List<RpslObject> mntIrtObjects = Lists.newArrayList();
        List<RpslAttribute> mntIrtAttributes = rpslObject.findAttributes(AttributeType.MNT_IRT);
        for (RpslAttribute mntIrtAttribute : mntIrtAttributes) {
            final String queryString = String.format("%s %s %s %s %s",
                    QueryFlag.NO_GROUPING.getLongFlag(),
                    QueryFlag.SELECT_TYPES.getLongFlag(),
                    IRT,
                    QueryFlag.NO_FILTERING.getLongFlag(),
                    mntIrtAttribute.getCleanValue().toString());
            final Query query = Query.parse(queryString);
            for (final RpslObject resultObject : runQuery(query, null, true)) {
                if (resultObject.getType().equals(IRT)) {
                    mntIrtObjects.add(resultObject);
                }
            }
        }

        return mntIrtObjects;
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

    private void mapAcceptableMediaType(Response.ResponseBuilder response, List<MediaType> mediaTypes) {
        if (mediaTypes != null) {
            for (MediaType mediaType : mediaTypes) {
                if (mediaType.equals(MediaType.TEXT_HTML_TYPE)) {
                    response.type(MediaType.TEXT_PLAIN_TYPE);
                    return;
                } else if (mediaType.equals(MediaType.APPLICATION_JSON) || mediaType.equals(RdapJsonProvider.CONTENT_TYPE_RDAP_JSON)) {
                    /* The response type must be
                     * application/rdap+json when the Accept header is
                     * application/json. See 'using-http', [4.7]. */
                    response.type(RdapJsonProvider.CONTENT_TYPE_RDAP_JSON);
                    return;
                }
            }
        }
    }
}
