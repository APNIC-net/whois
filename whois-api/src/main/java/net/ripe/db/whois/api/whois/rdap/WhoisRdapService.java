package net.ripe.db.whois.api.whois.rdap;

import java.io.Writer;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.util.Arrays;

import com.google.common.base.Function;
import com.google.common.base.Joiner;
import com.google.common.base.Stopwatch;
import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import com.google.common.net.InetAddresses;
import net.ripe.db.whois.api.whois.rdap.DelegatedStatsService;
import net.ripe.db.whois.api.freetext.FreeTextIndex;
import net.ripe.db.whois.api.whois.ApiResponseHandler;
import net.ripe.db.whois.api.search.IndexTemplate;
import net.ripe.db.whois.api.whois.rdap.domain.RdapObject;
import net.ripe.db.whois.common.dao.RpslObjectDao;
import net.ripe.db.whois.common.domain.CIString;
import net.ripe.db.whois.common.domain.IpInterval;
import net.ripe.db.whois.common.domain.ResponseObject;
import net.ripe.db.whois.common.domain.attrs.AttributeParseException;
import net.ripe.db.whois.common.domain.attrs.AutNum;
import net.ripe.db.whois.common.domain.attrs.Domain;
import net.ripe.db.whois.common.source.SourceContext;
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
import org.apache.lucene.analysis.Analyzer;
import org.apache.lucene.analysis.TokenStream;
import org.apache.lucene.analysis.core.LowerCaseFilter;
import org.apache.lucene.analysis.core.WhitespaceTokenizer;
import org.apache.lucene.analysis.miscellaneous.WordDelimiterFilter;
import org.apache.lucene.analysis.util.CharArraySet;
import org.apache.lucene.document.Document;
import org.apache.lucene.facet.taxonomy.TaxonomyReader;
import org.apache.lucene.index.IndexReader;
import org.apache.lucene.index.IndexableField;
import org.apache.lucene.queryparser.classic.MultiFieldQueryParser;
import org.apache.lucene.queryparser.classic.ParseException;
import org.apache.lucene.queryparser.classic.QueryParser;
import org.apache.lucene.search.IndexSearcher;
import org.apache.lucene.search.ScoreDoc;
import org.apache.lucene.search.TopDocs;
import org.apache.lucene.util.Version;
import org.joda.time.LocalDateTime;
import org.codehaus.enunciate.modules.jersey.ExternallyManagedLifecycle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import net.ripe.db.whois.api.whois.rdap.domain.Help;

import javax.annotation.Nullable;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.io.Reader;
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

    private static final int SEARCH_MAX_RESULTS = 1000;
    private static final Set<String> SEARCH_INDEX_FIELDS_NOT_MAPPED_TO_RPSL_OBJECT = Sets.newHashSet("primary-key", "object-type", "lookup-key");
    protected static Properties properties;
    protected static String rdapPropertiesPath = System.getProperty("rdap.config","");

    private static final int NOT_IMPLEMENTED = 501;

    static {
        initProperties();
    }

    private final QueryHandler queryHandler;
    private final RpslObjectDao objectDao;
    private final AbuseCFinder abuseCFinder;
    private final DelegatedStatsService delegatedStatsService;
    private final FreeTextIndex freeTextIndex;
    private final NoticeFactory noticeFactory;
    private final String source;
    private final String baseUrl;

    private String port43 = (String)properties.get("rdap.port43");

    private static Response.ResponseBuilder addResponseHeaders(HttpHeaders httpHeaders, Response.ResponseBuilder response) {
        mapAcceptableMediaType(response, httpHeaders.getAcceptableMediaTypes());
        return response.header("Access-Control-Allow-Origin", "*");
    }

    private Response.ResponseBuilder getUnsupportedOperationResponse(HttpServletRequest request) {
        String url = getRequestUrl(request);
        LOGGER.error(String.format("RDAP query for unsupported object type: %s", url));
        return Response.status(NOT_IMPLEMENTED).entity(RdapException.build(NOT_IMPLEMENTED, "Not Implemented", url, Arrays.asList("This type of request is not supported by this server."), noticeFactory, true));
    }

    private Response.ResponseBuilder getBadRequestResponse(HttpServletRequest request) {
        String url = getRequestUrl(request);
        LOGGER.error(String.format("RDAP query with malformed syntax: %s", url));
        return Response.status(Response.Status.BAD_REQUEST.getStatusCode()).entity(RdapException.build(Response.Status.BAD_REQUEST, url, noticeFactory));
    }

    @Autowired
    public WhoisRdapService(final QueryHandler queryHandler, 
                            final RpslObjectDao objectDao, 
                            final AbuseCFinder abuseCFinder,
                            final DelegatedStatsService delegatedStatsService,
                            final FreeTextIndex freeTextIndex,
                            final SourceContext sourceContext,
                            final NoticeFactory noticeFactory,
                            @Value("${rdap.port43:}") final String port43,
                            @Value("${rdap.public.baseurl:}") final String baseUrl) {
        this.queryHandler          = queryHandler;
        this.objectDao             = objectDao;
        this.abuseCFinder          = abuseCFinder;
        this.delegatedStatsService = delegatedStatsService;
        this.freeTextIndex         = freeTextIndex;
        this.baseUrl               = baseUrl;
        this.noticeFactory         = noticeFactory;
        this.port43                = port43;
        if (sourceContext != null) {
            this.source = sourceContext.getCurrentSource()
                                       .getName().toString();
        } else {
            this.source = "";
        }
    }

    @GET
    @Produces( { RdapJsonProvider.CONTENT_TYPE_RDAP_JSON, MediaType.APPLICATION_JSON, MediaType.TEXT_PLAIN } )
    @Path("/{objectType}/{key:.*}")
    public Response lookup(@Context final HttpServletRequest request,
                           @Context HttpHeaders httpHeaders,
                           @PathParam("objectType") final String objectType,
                           @PathParam("key") final String key) {

        Response.ResponseBuilder response = null;
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

                case "nameserver":
                    throw new UnsupportedOperationException();
            }

            if (whoisObjectTypes.isEmpty()) {
                throw new WebApplicationException(Response.Status.BAD_REQUEST);
            }

            RdapObject obj = null;
            try {
                obj = lookupObject(request, whoisObjectTypes, getKey(whoisObjectTypes, key));
            } catch (WebApplicationException webex) {
                int statusCode = webex.getResponse().getStatus();
                if (statusCode == 404) {
                    Query q = getLookupQuery(whoisObjectTypes, getKey(whoisObjectTypes, key));
                    response = redirect(request.getRequestURL().toString(), q);
                } else {
                    throw webex;
                }
            }
            if ((response == null) && (obj != null)) {
                response = Response.ok(obj);
            }
        } catch (WebApplicationException webex) {
            LOGGER.error(String.format("RDAP http error status [%s] caused by request [%s]: %s", webex.getResponse().getStatus(), getRequestUrl(request), webex.toString()));
            int statusCode = webex.getResponse().getStatus();
            response = Response.status(statusCode).entity(RdapException.build(Response.Status.fromStatusCode(statusCode), selfUrl, noticeFactory));
        } catch (SyntaxNotValidHereException snvhe) {
            LOGGER.error(String.format("RDAP query with spec-valid but here-invalid syntax: %s", getRequestUrl(request)));
            response = Response.status(Response.Status.NOT_FOUND.getStatusCode()).entity(RdapException.build(Response.Status.NOT_FOUND, selfUrl, Arrays.asList("The syntax used for this request is invalid for this particular server."), noticeFactory, false));
        } catch (UnsupportedOperationException uoe) {
            response = getUnsupportedOperationResponse(request);
        } catch (IllegalArgumentException iae) {
            response = getBadRequestResponse(request);
        } catch (Throwable t) {
            LOGGER.error("RDAP Internal Server error", t);
            // catch Everything
            response = Response.status(Response.Status.INTERNAL_SERVER_ERROR.getStatusCode()).entity(RdapException.build(Response.Status.INTERNAL_SERVER_ERROR, selfUrl, noticeFactory));
        }
        addResponseHeaders(httpHeaders, response);
        return response.build();
    }

    private Response.ResponseBuilder redirect(final String requestPath, final Query query) {
        final URI uri = delegatedStatsService.getUriForRedirect(requestPath, query);
        return Response.status(Response.Status.MOVED_PERMANENTLY).location(uri);
    }

    @GET
    @Produces( { RdapJsonProvider.CONTENT_TYPE_RDAP_JSON, MediaType.APPLICATION_JSON, MediaType.TEXT_PLAIN})
    @Path("/help")
    public Response lookupHelp(@Context final HttpServletRequest request, @Context HttpHeaders httpHeaders) {
        final String selfUrl =  getBaseUrl(request) + "/help";
        final Help help = new Help();
        help.getRdapConformance().addAll(RdapObjectMapper.RDAP_CONFORMANCE_LEVEL);
        help.getNotices().addAll(noticeFactory.generateHelpNotices(selfUrl));
        final Response.ResponseBuilder response = Response.ok().entity(help);
        addResponseHeaders(httpHeaders, response);
        return response.build();
    }

    @GET
    @Path("/")
    public Response redirectToDocumentation(@Context final HttpServletRequest request) {
        return Response.status(Response.Status.MOVED_PERMANENTLY).location(URI.create(getBaseUrl(request) + "/help")).build();
    }

    private static void initProperties() {
        if (properties == null) {
            if (rdapPropertiesPath.equals("")) {
                rdapPropertiesPath = "classpath:rdap.properties";
            } else {
                rdapPropertiesPath = "file:" + rdapPropertiesPath;
            }
            try {
                ApplicationContext appContext = new ClassPathXmlApplicationContext();
                Resource resource = appContext.getResource(rdapPropertiesPath);
                LOGGER.info(String.format("Loading [%s] from [%s]",rdapPropertiesPath, resource.getURL().toExternalForm()));
                Properties loadProperties = new Properties();
                loadProperties.load(resource.getInputStream());
                properties = loadProperties;
            } catch (IOException ioex) {
                String error = String.format("Failed to load properties file [%s]", rdapPropertiesPath);
                LOGGER.error(error);
                throw new ExceptionInInitializerError(error);
            }
        }
    }

    private void validateDomain(final String key) {
        try {
            Domain.parse(key);
        } catch (AttributeParseException e) {
            /* Very strictly speaking, this should be returning a 404
             * for a valid domain name (of any type) and a 400
             * otherwise. However, a 'proper' IDN library can't be
             * found at the moment, so unless one exists, or there's
             * some other easy way to validate a domain name, this
             * will return a 400 with a note about the syntax not
             * being supported here for arguments that aren't reverse
             * domains, or one of the other special types handled by
             * the server. */
            throw new SyntaxNotValidHereException();
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
                throw new SyntaxNotValidHereException();
            }
        } else if (key.toUpperCase().startsWith("IRT-")) {
            if (!AttributeType.IRT.isValidValue(IRT, key)) {
                throw new SyntaxNotValidHereException();
            }
        } else {
            if (!AttributeType.NIC_HDL.isValidValue(ObjectType.PERSON, key)) {
                throw new SyntaxNotValidHereException();
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
        final List<RpslObject> result = runQuery(query, request, true, false);
        return !result.isEmpty();
    }

    protected RdapObject handleQuery(final Query query, final HttpServletRequest request) {
        try {
            final List<RpslObject> result = runQuery(query, request, false, true);
            if (result.isEmpty()) {
                throw new WebApplicationException(Response.status(Response.Status.NOT_FOUND).build());
            }

            final RpslObject resultObject = result.remove(0);

            List<RpslObject> abuseContacts = Lists.newArrayList();
            abuseContacts.addAll(getAbuseContacts(resultObject));
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
                    port43,
                    noticeFactory);

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
        initProperties();
        return properties;
    }

    private List<RpslObject> runQuery(final Query query, final HttpServletRequest request, final boolean internalRequest, final boolean ignoreIana) {
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
        final boolean[] returnNothing = new boolean[1];
        returnNothing[0] = false;

        try {
            queryHandler.streamResults(query, queryAddress, contextId, new ApiResponseHandler() {
                @Override
                public void handle(final ResponseObject responseObject) {
                    if (responseObject instanceof RpslObject) {
                        RpslObject ro = (RpslObject) responseObject; 
                        /* If an 'IANA' object is found in the query results,
                           and ignoreIana is true, then return an empty result
                           list. (In this instance, the presence of an IANA
                           (placeholder) object indicates a 404. The caller
                           can't determine that, though, if miscellaneous
                           related objects are returned as well.)
                           */
                        result.add(ro);
                        List<RpslAttribute> admins =
                            ro.findAttributes(AttributeType.ADMIN_C);
                        if (admins != null) {
                            for (RpslAttribute admin : admins) {
                                if (admin.getCleanValue().toString().equals("IANA1-AP")) {
                                    returnNothing[0] = true;
                                }
                            }
                        }
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

        if (returnNothing[0]) {
            List<RpslObject> actualResult = Lists.newArrayList();
            return actualResult;
        }
        return result;
    }

    public String getBaseUrl(final HttpServletRequest request) {
        if (StringUtils.isNotEmpty(this.baseUrl)) {
            return this.baseUrl;
        }

        final StringBuffer buffer = request.getRequestURL();
        buffer.setLength(buffer.length() - request.getRequestURI().length() + request.getServletPath().length());

        return buffer.toString();
    }

    private Query getLookupQuery(final Set<ObjectType> objectTypes, final String key) {
        final String objectTypesString = COMMA_JOINER.join(Iterables.transform(objectTypes, new Function<ObjectType, String>() {
            @Override
            public String apply(final ObjectType input) {
                return input.getName();
            }
        }));
        return getLookupQuery(objectTypesString, key);
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
                true,
                false
            );
            if (parents.size() > 0) {
                return parents.get(0);
            }
        }
        return null;
    }

    public static String getAcceptableMediaType(List<MediaType> mediaTypes) {
        if ((mediaTypes == null) || (mediaTypes.size() == 0)) {
            return RdapJsonProvider.CONTENT_TYPE_RDAP_JSON;
        }
        for (MediaType mediaType : mediaTypes) {
            if (mediaType.isCompatible(MediaType.APPLICATION_JSON_TYPE) || mediaType.isCompatible(RdapJsonProvider.CONTENT_TYPE_RDAP_JSON_TYPE)) {
                return RdapJsonProvider.CONTENT_TYPE_RDAP_JSON;
            }
            if (mediaType.isCompatible(MediaType.TEXT_HTML_TYPE) || mediaType.isCompatible(MediaType.TEXT_PLAIN_TYPE)) {
                return MediaType.TEXT_PLAIN;
            }
        }
        return null;
    }

    private static void mapAcceptableMediaType(Response.ResponseBuilder response, List<MediaType> mediaTypes) {
        String mediaType = getAcceptableMediaType(mediaTypes);
        if (mediaType != null) {
            response.type(mediaType);
        }
    }

    @GET
    @Produces({MediaType.APPLICATION_JSON, RdapJsonProvider.CONTENT_TYPE_RDAP_JSON, MediaType.TEXT_PLAIN})
    @Path("/entities")
    public Response searchEntities(
            @Context final HttpServletRequest request,
            @Context final HttpHeaders httpHeaders,
            @QueryParam("fn") final String name,
            @QueryParam("handle") final String handle) {
        if (name != null && handle == null) {
            return handleSearch("entity", new String[]{"person", "role", "org-name"}, name, request, httpHeaders);
        }

        if (name == null && handle != null) {
            return handleSearch("entity", new String[]{"organisation", "nic-hdl"}, handle, request, httpHeaders);
        }

        return addResponseHeaders(httpHeaders, getBadRequestResponse(request)).build();
    }

    @GET
    @Produces({MediaType.APPLICATION_JSON, RdapJsonProvider.CONTENT_TYPE_RDAP_JSON, MediaType.TEXT_PLAIN})
    @Path("/nameservers")
    public Response searchNameservers(
            @Context final HttpServletRequest request,
            @Context final HttpHeaders httpHeaders,
            @QueryParam("name") final String name) {
        return addResponseHeaders(httpHeaders, getUnsupportedOperationResponse(request)).build();
    }

    @GET
    @Produces({MediaType.APPLICATION_JSON, RdapJsonProvider.CONTENT_TYPE_RDAP_JSON, MediaType.TEXT_PLAIN})
    @Path("/domains")
    public Response searchDomains(
            @Context final HttpServletRequest request,
            @Context final HttpHeaders httpHeaders,
            @QueryParam("name") final String name,
            @QueryParam("nsIp") final String nsIp,
            @QueryParam("nsLdhName") final String nsLdhName) {
        if (!StringUtils.isEmpty(nsIp) || !StringUtils.isEmpty(nsLdhName)) {
            return addResponseHeaders(httpHeaders, getUnsupportedOperationResponse(request)).build();
        }
        if (StringUtils.isEmpty(name)) {
            return addResponseHeaders(httpHeaders, getBadRequestResponse(request)).build();
        }

        return handleSearch("domain", new String[]{"domain"}, name, request, httpHeaders);
    }

    private Response handleSearch(final String objectType, final String[] fields, final String term, final HttpServletRequest request, final HttpHeaders httpHeaders) {
        LOGGER.info("Search {} for {}", fields, term);
        try {
            final boolean[] isTruncated = new boolean[1];
            isTruncated[0] = false;
            final List<RpslObject> objects = freeTextIndex.search(new IndexTemplate.SearchCallback<List<RpslObject>>() {
                @Override
                public List<RpslObject> search(IndexReader indexReader, TaxonomyReader taxonomyReader, IndexSearcher indexSearcher) throws IOException {
                    final Stopwatch stopWatch = new Stopwatch().start();
                    List<RpslObject> results = Lists.newArrayList();
                    try {
                        final QueryParser queryParser = new MultiFieldQueryParser(Version.LUCENE_44, fields, new RdapAnalyzer());
                        queryParser.setAllowLeadingWildcard(true);
                        queryParser.setDefaultOperator(QueryParser.Operator.AND);
                        final org.apache.lucene.search.Query query = queryParser.parse(term);
                        final TopDocs topDocs = indexSearcher.search(query, SEARCH_MAX_RESULTS + 1);
                        for (ScoreDoc scoreDoc : topDocs.scoreDocs) {
                            final Document document = indexSearcher.doc(scoreDoc.doc);
                            results.add(convertLuceneDocumentToRpslObject(document));
                        }
                        if (results.size() >= (SEARCH_MAX_RESULTS + 1)) {
                            isTruncated[0] = true;
                            results = results.subList(0, SEARCH_MAX_RESULTS);
                        }

                        LOGGER.info("Found {} objects in {}", results.size(), stopWatch.stop());
                        return results;
                    } catch (ParseException e) {
                        throw new IllegalArgumentException(e);
                    }
                }
            });

            final Iterable<LocalDateTime> lastUpdateds = Iterables.transform(objects, new Function<RpslObject, LocalDateTime>() {
                @Nullable
                @Override
                public LocalDateTime apply(@Nullable RpslObject input) {
                    return objectDao.getLastUpdated(input.getObjectId());
                }
            });

            RdapObject result =
                RdapObjectMapper.mapSearch(objectType,
                                           getRequestUrl(request),
                                           baseUrl,
                                           objects,
                                           lastUpdateds,
                                           noticeFactory,
                                           isTruncated[0]);

            Response.ResponseBuilder searchResponse = Response.status(Response.Status.OK);
            searchResponse.entity(result);
            addResponseHeaders(httpHeaders, searchResponse);
            return searchResponse.build();
        } catch (IOException e) {
            LOGGER.error("Caught IOException", e);
            throw new IllegalStateException(e);
        } catch (Exception e) {
            LOGGER.error("Caught Exception", e);
            throw e;
        }
    }

    private RpslObject convertLuceneDocumentToRpslObject(Document document) {
        final List<RpslAttribute> attributes = Lists.newArrayList();
        int objectId = 0;

        for (final IndexableField field : document.getFields()) {
            if (SEARCH_INDEX_FIELDS_NOT_MAPPED_TO_RPSL_OBJECT.contains(field.name())) {
                if ("primary-key".equals(field.name())) {
                    objectId = Integer.parseInt(field.stringValue());
                }
            } else {
                /* Objects may contain attributes that are no longer valid. Try
                 * to get the attribute by name first, and skip it if it is
                 * invalid. */
                AttributeType attributeType;
                try {
                    attributeType = AttributeType.getByName(field.name());
                } catch (IllegalArgumentException ie) {
                    attributeType = null;
                }
                if (attributeType != null) {
                    attributes.add(new RpslAttribute(attributeType, field.stringValue()));
                }
            }
        }

        attributes.add(new RpslAttribute(AttributeType.SOURCE, source));
        return new RpslObject(objectId, attributes);
    }

    private class RdapAnalyzer extends Analyzer {
        @Override
        protected TokenStreamComponents createComponents(final String fieldName, final Reader reader) {
            final WhitespaceTokenizer tokenizer = new WhitespaceTokenizer(Version.LUCENE_44, reader);
            TokenStream tok = new WordDelimiterFilter(
                    tokenizer,
                    WordDelimiterFilter.PRESERVE_ORIGINAL,
                    CharArraySet.EMPTY_SET);
            tok = new LowerCaseFilter(Version.LUCENE_44, tok);
            return new TokenStreamComponents(tokenizer, tok);
        }
    }
}
