package net.ripe.db.whois.query.planner;

import com.google.common.base.Function;
import com.google.common.base.Predicates;
import com.google.common.collect.Iterables;
import com.google.common.collect.Sets;
import net.ripe.db.whois.common.dao.RpslObjectDao;
import net.ripe.db.whois.common.domain.CIString;
import net.ripe.db.whois.common.domain.ResponseObject;
import net.ripe.db.whois.common.rpsl.RpslObject;
import net.ripe.db.whois.common.rpsl.transform.FilterAuthFunction;
import net.ripe.db.whois.common.rpsl.transform.FilterEmailFunction;
import net.ripe.db.whois.common.source.SourceContext;
import net.ripe.db.whois.query.domain.MessageObject;
import net.ripe.db.whois.query.domain.QueryMessages;
import net.ripe.db.whois.query.executor.decorators.FilterPersonalDecorator;
import net.ripe.db.whois.query.executor.decorators.FilterPlaceholdersDecorator;
import net.ripe.db.whois.query.executor.decorators.FilterTagsDecorator;
import net.ripe.db.whois.query.query.Query;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.annotation.CheckForNull;
import javax.annotation.Nullable;
import java.util.Collections;
import java.util.Set;

// TODO [AK] Wrap related response objects (messages + rpsl) in a single response object

// TODO [AK] Merge into SearchQueryExecutor

/**
 * Converts a query into an query result. Typically queries results are stored as proxies
 * and object data is loaded as the result is being written to the client (lazy evaluation).
 */
@Component
public class RpslResponseDecorator {
    // TODO: [AH] refactor this class; there are 3 different ways to write a decorator ATM!
    private static final FilterEmailFunction FILTER_EMAIL_FUNCTION = new FilterEmailFunction();
    private static final FilterAuthFunction FILTER_AUTH_FUNCTION = new FilterAuthFunction();

    private final RpslObjectDao rpslObjectDao;
    private final FilterPersonalDecorator filterPersonalDecorator;
    private final SourceContext sourceContext;
    private final AbuseCFunction abuseCFunction;
    private final ToBriefFunction toBriefFunction;
    private final DummifyFunction dummifyFunction;
    private final FilterTagsDecorator filterTagsDecorator;
    private final FilterPlaceholdersDecorator filterPlaceholdersDecorator;
    private final Set<PrimaryObjectDecorator> decorators;
    private final String source;

    @Autowired
    public RpslResponseDecorator(final RpslObjectDao rpslObjectDao,
                                 final FilterPersonalDecorator filterPersonalDecorator,
                                 final SourceContext sourceContext,
                                 final AbuseCFinder abuseCFinder,
                                 final DummifyFunction dummifyFunction,
                                 final FilterTagsDecorator filterTagsDecorator,
                                 final FilterPlaceholdersDecorator filterPlaceholdersDecorator,
                                 final @Value("${whois.source}") String source,
                                 final PrimaryObjectDecorator... decorators) {
        this.rpslObjectDao = rpslObjectDao;
        this.filterPersonalDecorator = filterPersonalDecorator;
        this.sourceContext = sourceContext;
        this.dummifyFunction = dummifyFunction;
        this.filterTagsDecorator = filterTagsDecorator;
        this.filterPlaceholdersDecorator = filterPlaceholdersDecorator;
        this.abuseCFunction = new AbuseCFunction(abuseCFinder);
        this.toBriefFunction = new ToBriefFunction(abuseCFinder);
        this.decorators = Sets.newHashSet(decorators);
        this.source = source;
    }

    public Iterable<? extends ResponseObject> getResponse(final Query query, Iterable<? extends ResponseObject> result) {
        result = filterPlaceholdersDecorator.decorate(query, result);
        result = dummify(result);

        result = groupRelatedObjects(query, result);
        result = filterTagsDecorator.decorate(query, result);
        result = filterPersonalDecorator.decorate(query, result);

        result = applyAbuseC(query, result);
        result = filterEmail(query, result);
        result = filterAuth(result);

        result = applyOutputFilters(query, result);

        return result;
    }

    private Iterable<? extends ResponseObject> applyAbuseC(final Query query, final Iterable<? extends ResponseObject> result) {
        if (!query.isBrief() && sourceContext.getCurrentSource().getName().equals(CIString.ciString(source))) {
            return Iterables.concat(Iterables.transform(result, abuseCFunction));
        }

        return result;
    }

    private Iterable<? extends ResponseObject> dummify(final Iterable<? extends ResponseObject> result) {
        if (sourceContext.isDummificationRequired()) {
            return Iterables.filter(Iterables.transform(result, dummifyFunction), Predicates.notNull());
        }

        return result;
    }

    private Iterable<? extends ResponseObject> groupRelatedObjects(final Query query, Iterable<? extends ResponseObject> primaryObjects) {
        final GroupFunction groupFunction = getGroupFunction(query);
        if (groupFunction == null) {
            return primaryObjects;
        }

        final Iterable<ResponseObject> groupInline = Iterables.concat(Iterables.transform(primaryObjects, groupFunction));

        return Iterables.concat(
                groupInline,
                groupFunction.getGroupedAfter());
    }

    @CheckForNull
    private GroupFunction getGroupFunction(final Query query) {
        if (query.isPrimaryObjectsOnly()) {
            return null;
        }

        if (query.isGrouping()) {
            return new GroupRelatedFunction(rpslObjectDao, query, decorators);
        }

        return new GroupObjectTypesFunction(rpslObjectDao, query, decorators);
    }

    private Iterable<? extends ResponseObject> filterAuth(final Iterable<? extends ResponseObject> objects) {
        return Iterables.transform(objects, new Function<ResponseObject, ResponseObject>() {
            @Nullable
            @Override
            public ResponseObject apply(final ResponseObject input) {
                if (input instanceof RpslObject) {
                    return FILTER_AUTH_FUNCTION.apply((RpslObject) input);
                }

                return input;
            }
        });
    }

    private Iterable<? extends ResponseObject> filterEmail(final Query query, final Iterable<? extends ResponseObject> groupedObjects) {
        if (!sourceContext.isAcl() || !query.isFiltered() || query.isBrief()) {
            return groupedObjects;
        }

        return Iterables.concat(Collections.singletonList(new MessageObject(QueryMessages.outputFilterNotice())), Iterables.transform(groupedObjects, new Function<ResponseObject, ResponseObject>() {
            @Nullable
            @Override
            public ResponseObject apply(final ResponseObject input) {
                if (input instanceof RpslObject) {
                    return FILTER_EMAIL_FUNCTION.apply((RpslObject) input);
                }

                return input;
            }
        }));
    }

    private Iterable<? extends ResponseObject> applyOutputFilters(final Query query, final Iterable<? extends ResponseObject> objects) {
        if (query.isShortHand()) {
            return Iterables.transform(objects, new ToShorthandFunction());
        }

        if (query.isBrief()) {
            return Iterables.filter(Iterables.transform(objects, toBriefFunction), Predicates.notNull());
        }

        if (query.isKeysOnly()) {
            return Iterables.concat(
                    Collections.singletonList(new MessageObject(QueryMessages.primaryKeysOnlyNotice())),
                    Iterables.transform(objects, new ToKeysFunction()));
        }

        return objects;
    }
}
