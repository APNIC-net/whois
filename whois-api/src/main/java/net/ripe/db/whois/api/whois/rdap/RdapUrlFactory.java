package net.ripe.db.whois.api.whois.rdap;

import com.google.common.collect.Maps;
import net.ripe.db.whois.api.whois.rdap.domain.Link;
import net.ripe.db.whois.api.whois.rdap.domain.RdapObject;
import org.apache.commons.lang.StringUtils;
import org.eclipse.jetty.util.URIUtil;

import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Map;

/**
 * Stores information about an RDAP request
 * and uses this information to provide a
 * common interface to the generation of
 * URLs used in RDAP responses.
 *
 * @author bwinters@apnic.net
 */
class RdapUrlFactory {
    private static final String X_FORWARDED_PROTO_HEADER = "X-Forwarded-Proto";
    private static final String HELP_PATH = "/help";

    private final String baseUrl;
    private final String requestUrl;


    public RdapUrlFactory(final HttpServletRequest request) {
        // This constructor used for testing only.
        this.baseUrl = generateBaseUrl(request, null);
        this.requestUrl = generateRequestUrl(request, this.baseUrl);
    }

    public RdapUrlFactory(final HttpServletRequest request, final String baseUrl) {
        this(request, buildSchemeToUrlMap(baseUrl));
    }

    public RdapUrlFactory(final HttpServletRequest request, final Map<String, String> baseUrls) {
        this.baseUrl = generateBaseUrl(request, baseUrls);
        this.requestUrl = generateRequestUrl(request, this.baseUrl);
    }

    public RdapUrlFactory(final String requestUrl, final String baseUrl) {
        this.baseUrl = baseUrl;
        this.requestUrl = requestUrl;
    }

    public static Map<String, String> buildSchemeToUrlMap(final String urls) {
        final Map<String, String> schemeToUrlMap = Maps.newHashMap();
        if (StringUtils.isNotEmpty(urls)) {
            final String[] urlsArr = urls.split(",");
            for (String url : urlsArr) {
                final String scheme = url.replaceFirst("://.*$", "").toLowerCase();
                schemeToUrlMap.put(scheme, url);
            }
        }
        return schemeToUrlMap;
    }

    public static String getScheme(final HttpServletRequest request) {
        final String xForwardedProtoHeader = request.getHeader(X_FORWARDED_PROTO_HEADER);
        if (StringUtils.isNotEmpty(xForwardedProtoHeader)) {
            return xForwardedProtoHeader.toLowerCase();
        } else {
            return request.getScheme().toLowerCase();
        }
    }

    private static String generateBaseUrl(final HttpServletRequest request, final Map<String, String> baseUrls) {
        /*
         * BaseUrl generation logic is as follows:
         *
         * A list of base urls may optionally be provided.
         * -> If no base url is provided then a base url will
         *    be dynamically generated using the scheme specified
         *    in the request.
         * -> If one or more base urls have been specified an
         *    attempt is made to match the scheme specified in
         *    the request with one of the provided base urls.
         *    If no match is found then the first specified
         *    base url in the list of base urls is used instead.
         */
        final String scheme = getScheme(request);
        if (baseUrls != null && !baseUrls.isEmpty()) {
            String baseUrl = baseUrls.get(scheme);
            if (StringUtils.isEmpty(baseUrl)) {
                baseUrl = baseUrls.entrySet().iterator().next().getValue();
            }
            return baseUrl;
        }
        return generateDynamicBaseUrl(request, scheme);
    }

    private static String generateDynamicBaseUrl(final HttpServletRequest request, final String scheme) {
        final StringBuffer buffer = request.getRequestURL();
        buffer.setLength(buffer.length() - request.getRequestURI().length() + request.getServletPath().length());
        if (!StringUtils.equals(request.getScheme().toLowerCase(), scheme)) {
            buffer.replace(0, request.getScheme().length(), scheme);
        }
        return buffer.toString();
    }

    private static String generateRequestUrl(final HttpServletRequest request, final String baseUrl) {
        final StringBuffer buffer = new StringBuffer();
        buffer.append(baseUrl);
        buffer.append(request.getPathInfo());
        if (StringUtils.isNotEmpty(request.getQueryString())) {
            buffer.append('?');
            buffer.append(request.getQueryString());
        }
        return buffer.toString();
    }

    public String getBaseUrl() {
        return baseUrl;
    }

    public String getRequestUrl() {
        return requestUrl;
    }

    public String generateObjectUrl(final String objectType, final Object obj) {
        return String.format("%s/%s/%s", getBaseUrl(), objectType, urlencode(obj));
    }

    public String generateSelfUrl(final RdapObject rdapObject) {
        final List<Link> links = rdapObject.getLinks();
        for (final Link link : links) {
            if (link.getRel().equals("self")) {
                return link.getHref();
            }
        }
        // Default the selfUrl to the requestUrl.
        return getRequestUrl();
    }

    public String getHelpUrl() {
        return new StringBuffer().append(getBaseUrl()).append(HELP_PATH).toString();
    }

    public static String urlencode(final Object obj) {
        return URIUtil.encodePath(String.valueOf(obj));
    }
}
