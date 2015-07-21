package net.ripe.db.whois.api.whois.rdap;


import com.google.common.base.Optional;
import com.google.common.base.Predicate;
import com.google.common.base.Splitter;
import com.google.common.collect.Iterables;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import net.ripe.db.whois.common.domain.CIString;
import net.ripe.db.whois.common.grs.AuthoritativeResource;
import net.ripe.db.whois.common.grs.AuthoritativeResourceData;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.query.query.Query;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.EmbeddedValueResolverAware;
import org.springframework.stereotype.Component;
import org.springframework.util.StringValueResolver;

import javax.annotation.PostConstruct;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;
import java.net.URI;
import java.util.Map;
import java.util.Set;

import static net.ripe.db.whois.common.domain.CIString.ciSet;

@Component
public class DelegatedStatsService implements EmbeddedValueResolverAware {
    private static final Logger LOGGER = LoggerFactory.getLogger(DelegatedStatsService.class);

    private static final Set<ObjectType> ALLOWED_OBJECTTYPES = Sets.newHashSet(ObjectType.AUT_NUM, ObjectType.INET6NUM, ObjectType.INETNUM);
    private final Map<CIString, Map<String, String>> sourceToPathMap = Maps.newHashMap();
    private final Set<CIString> sources;
    private final AuthoritativeResourceData resourceData;
    private StringValueResolver valueResolver;

    @Autowired
    public DelegatedStatsService(@Value("${rdap.sources:}") String rdapSourceNames,
                                 final AuthoritativeResourceData resourceData) {
        this.sources = ciSet(Splitter.on(',').split(rdapSourceNames));
        this.resourceData = resourceData;
    }

    @Override
    public void setEmbeddedValueResolver(StringValueResolver valueResolver) {
        this.valueResolver = valueResolver;
    }

    @PostConstruct
    void init() {
        for (CIString source : sources) {
            final String sourceName = source.toLowerCase().replace("-grs", "");
            final String propertyName = String.format("${rdap.redirect.%s:}", sourceName);
            final String redirectUrls = valueResolver.resolveStringValue(propertyName);
            if (!StringUtils.isBlank(redirectUrls)) {
                sourceToPathMap.put(source, RdapUrlFactory.buildSchemeToUrlMap(redirectUrls));
            }
        }
    }

    public URI getUriForRedirect(final String scheme, final String requestPath, final Query query) {
        final Optional<ObjectType> objectType = Iterables.tryFind(query.getObjectTypes(), new Predicate<ObjectType>() {
            @Override
            public boolean apply(ObjectType input) {
                return ALLOWED_OBJECTTYPES.contains(input);
            }
        });
        final ObjectType realObjectType =
            (objectType.isPresent())
                ? objectType.get()
          : (query.getObjectTypes().contains(ObjectType.AS_BLOCK))
                ? ObjectType.AUT_NUM
                : null;
        
        if (realObjectType != null) {
            for (Map.Entry<CIString, Map<String, String>> entry : sourceToPathMap.entrySet()) {
                final CIString sourceName = entry.getKey();
                final AuthoritativeResource authoritativeResource = resourceData.getAuthoritativeResource(sourceName);
                if (authoritativeResource.isMaintainedInRirSpace(realObjectType, CIString.ciString(query.getSearchValue()))) {
                    final Map<String, String> schemeToPathMap = entry.getValue();
                    if (!schemeToPathMap.isEmpty()) {
                        String basePath = schemeToPathMap.get(scheme.toLowerCase());
                        if (StringUtils.isEmpty(basePath)) {
                            basePath = schemeToPathMap.entrySet().iterator().next().getValue();
                        }
                        LOGGER.debug("Redirecting {} to {}", requestPath, sourceName);
                        // TODO: don't include local path prefix (lookup from base context and replace)
                        return URI.create(String.format("%s%s", basePath, requestPath.replaceFirst(".*/rdap", "")));
                    }
                }
            }
        }

        LOGGER.debug("Resource {} not found", query.getSearchValue());
        throw new WebApplicationException(Response.Status.NOT_FOUND);
    }
}
