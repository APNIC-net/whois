package net.ripe.db.whois.query.executor;

import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import net.ripe.db.whois.common.collect.CollectionHelper;
import net.ripe.db.whois.common.dao.RpslObjectDao;
import net.ripe.db.whois.common.dao.RpslObjectInfo;
import net.ripe.db.whois.common.domain.Identifiable;
import net.ripe.db.whois.common.domain.IpInterval;
import net.ripe.db.whois.common.domain.ResponseObject;
import net.ripe.db.whois.common.domain.attrs.AsBlockRange;
import net.ripe.db.whois.common.iptree.*;
import net.ripe.db.whois.common.rpsl.*;
import net.ripe.db.whois.query.dao.Inet6numDao;
import net.ripe.db.whois.query.dao.InetnumDao;
import net.ripe.db.whois.query.domain.MessageObject;
import net.ripe.db.whois.query.domain.QueryMessages;
import net.ripe.db.whois.query.query.Query;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Set;

@Component
class RpslObjectSearcher {
    private static final Set<AttributeType> INVERSE_ATTRIBUTE_TYPES;

    static {
        Set<AttributeType> supportAttributeTypes = Sets.newHashSet();
        for (final ObjectType objectType : ObjectType.values()) {
            supportAttributeTypes.addAll(ObjectTemplate.getTemplate(objectType).getInverseLookupAttributes());
        }

        INVERSE_ATTRIBUTE_TYPES = Sets.newEnumSet(supportAttributeTypes, AttributeType.class);
    }

    private final RpslObjectDao rpslObjectDao;
    private final InetnumDao inetnumDao;
    private final Inet6numDao inet6numDao;
    private final Ipv4Tree ipv4Tree;
    private final Ipv6Tree ipv6Tree;
    private final Ipv4RouteTree route4Tree;
    private final Ipv6RouteTree route6Tree;
    private final Ipv4DomainTree ipv4DomainTree;
    private final Ipv6DomainTree ipv6DomainTree;

    @Autowired
    public RpslObjectSearcher(
            final RpslObjectDao rpslObjectDao,
            final InetnumDao inetnumDao,
            final Inet6numDao inet6numDao,
            final Ipv4Tree ipv4Tree,
            final Ipv6Tree ipv6Tree,
            final Ipv4RouteTree route4Tree,
            final Ipv6RouteTree route6Tree,
            final Ipv4DomainTree ipv4DomainTree,
            final Ipv6DomainTree ipv6DomainTree) {
        this.rpslObjectDao = rpslObjectDao;
        this.inetnumDao = inetnumDao;
        this.inet6numDao = inet6numDao;
        this.ipv4Tree = ipv4Tree;
        this.ipv6Tree = ipv6Tree;
        this.route4Tree = route4Tree;
        this.route6Tree = route6Tree;
        this.ipv4DomainTree = ipv4DomainTree;
        this.ipv6DomainTree = ipv6DomainTree;
    }

    public Iterable<? extends ResponseObject> search(final Query query) {
        Iterable<ResponseObject> result = Collections.emptyList();

        if (query.isInverse()) {
            return indexLookupReverse(query);
        }

        for (final ObjectType objectType : query.getObjectTypes()) {
            if (query.matchesObjectType(objectType)) {
                result = Iterables.concat(result, executeForObjectType(query, objectType));
            }
        }

        return result;
    }

    private Iterable<ResponseObject> executeForObjectType(final Query query, final ObjectType type) {
        switch (type) {
            case AS_BLOCK:
                return asBlockLookup(query);
            case INETNUM:
                return query.getIpKeyOrNull() != null ? ipTreeLookup(ipv4Tree, query.getIpKeyOrNull(), query.matchOperations()) : proxy(inetnumDao.findByNetname(query.getSearchValue()));
            case INET6NUM:
                return query.getIpKeyOrNull() != null ? ipTreeLookup(ipv6Tree, query.getIpKeyOrNull(), query.matchOperations()) : proxy(inet6numDao.findByNetname(query.getSearchValue()));
            case DOMAIN:
                return domainLookup(query);
            case ROUTE:
                return ipTreeLookup(route4Tree, query.getIpKeyOrNull(), query.matchOperations());
            case ROUTE6:
                return ipTreeLookup(route6Tree, query.getIpKeyOrNull(), query.matchOperations());
            default:
                return indexLookup(query, type);
        }
    }

    private Iterable<ResponseObject> asBlockLookup(final Query query) {
        final AsBlockRange range = query.getAsBlockRangeOrNull();
        if (range != null) {
            final RpslObject asBlock = rpslObjectDao.findAsBlock(range.getBegin(), range.getEnd());
            if (asBlock != null) {
                return Collections.<ResponseObject>singletonList(asBlock);
            }
        }

        return Collections.emptyList();
    }

    private Iterable<ResponseObject> domainLookup(final Query query) {
        String searchValue = query.getSearchValue().toLowerCase();

        if (searchValue.endsWith("e164.arpa")) {
            return indexLookup(query, ObjectType.DOMAIN, searchValue);
        }

        final IpInterval<?> ipInterval = query.getIpKeyOrNullReverse();
        if (ipInterval == null) {
            return Collections.emptyList();
        }

        switch (ipInterval.getAttributeType()) {
            case INETNUM:
                return ipTreeLookup(ipv4DomainTree, ipInterval, query.matchOperations());
            case INET6NUM:
                return ipTreeLookup(ipv6DomainTree, ipInterval, query.matchOperations());
            default:
                throw new IllegalArgumentException(String.format("Unexpected type: %s", ipInterval.getAttributeType()));
        }
    }

    private Iterable<ResponseObject> ipTreeLookup(final IpTree tree, final IpInterval<?> key, final Set<Query.MatchOperation> matchOperations) {
        if (key == null) {
            return Collections.emptyList();
        }

        final Query.MatchOperation operation = matchOperations.isEmpty() ?
                Query.MatchOperation.MATCH_EXACT_OR_FIRST_LEVEL_LESS_SPECIFIC :
                matchOperations.iterator().next();

        return proxy(findEntries(key, tree, operation));
    }

    @SuppressWarnings("unchecked")
    private List<IpEntry> findEntries(final IpInterval key, final IpTree tree, final Query.MatchOperation operation) {
        switch (operation) {
            case MATCH_EXACT_OR_FIRST_LEVEL_LESS_SPECIFIC:
                return tree.findExactOrFirstLessSpecific(key);
            case MATCH_EXACT:
                return tree.findExact(key);
            case MATCH_FIRST_LEVEL_LESS_SPECIFIC:
                return tree.findFirstLessSpecific(key);
            case MATCH_EXACT_AND_ALL_LEVELS_LESS_SPECIFIC:
                return tree.findExactAndAllLessSpecific(key);
            case MATCH_FIRST_LEVEL_MORE_SPECIFIC:
                return tree.findFirstMoreSpecific(key);
            case MATCH_ALL_LEVELS_MORE_SPECIFIC:
                return tree.findAllMoreSpecific(key);
            default:
                throw new IllegalArgumentException("Operation not supported by IpTree: " + operation);
        }
    }

    private Iterable<ResponseObject> indexLookup(final Query query, final ObjectType type) {
        if (query.isKeysOnly() && (ObjectType.PERSON.equals(type) || ObjectType.ROLE.equals(type) || ObjectType.ORGANISATION.equals(type))) {
            return Collections.emptyList();
        }

        return indexLookup(query, type, query.getSearchValue());
    }

    private Iterable<ResponseObject> indexLookup(final Query query, final ObjectType type, final String searchValue) {
        final ObjectTemplate objectTemplate = ObjectTemplate.getTemplate(type);
        final Set<AttributeType> keyAttributes = objectTemplate.getKeyAttributes();

        final Set<RpslObjectInfo> result = Sets.newTreeSet();
        for (final AttributeType lookupAttribute : objectTemplate.getLookupAttributes()) {
            if (!query.MatchesObjectTypeAndAttribute(type, lookupAttribute)) {
                continue;
            }

            if (keyAttributes.contains(lookupAttribute)) {
                try {
                    result.add(rpslObjectDao.findByKey(type, searchValue));
                } catch (EmptyResultDataAccessException ignored) {
                }
            } else {
                result.addAll(RpslObjectFilter.filterByType(type, rpslObjectDao.findByAttribute(lookupAttribute, searchValue)));
            }
        }

        return proxy(result);
    }

    private Iterable<ResponseObject> indexLookupReverse(final Query query) {
        final List<ResponseObject> errors = Lists.newArrayList();
        for (final AttributeType attributeType : query.getAttributeTypes()) {
            if (!INVERSE_ATTRIBUTE_TYPES.contains(attributeType)) {
                errors.add(new MessageObject(QueryMessages.attributeNotSearchable(attributeType.getName())));
            }
        }

        if (!errors.isEmpty()) {
            return errors;
        }

        final Set<ObjectType> objectTypes = query.getObjectTypes();

        final Set<RpslObjectInfo> result = Sets.newTreeSet();
        for (final AttributeType attributeType : query.getAttributeTypes()) {
            final String searchValue = query.getSearchValue();
            final Collection<RpslObjectInfo> objectInfos = rpslObjectDao.findByAttribute(attributeType, searchValue);
            for (final RpslObjectInfo objectInfo : objectInfos) {
                if (objectTypes.contains(objectInfo.getObjectType())) {
                    result.add(objectInfo);
                }
            }
        }

        return proxy(result);
    }

    private Iterable<ResponseObject> proxy(final Iterable<? extends Identifiable> identifiables) {
        return CollectionHelper.iterateProxy(rpslObjectDao, identifiables);
    }
}
