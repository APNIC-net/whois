package net.ripe.db.whois.query.executor;

import com.google.common.collect.Lists;
import net.ripe.db.whois.common.dao.VersionDao;
import net.ripe.db.whois.common.dao.VersionInfo;
import net.ripe.db.whois.common.dao.VersionLookupResult;
import net.ripe.db.whois.common.domain.ResponseObject;
import net.ripe.db.whois.common.domain.VersionDateTime;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.RpslObject;
import net.ripe.db.whois.query.domain.*;
import net.ripe.db.whois.query.planner.VersionResponseDecorator;
import net.ripe.db.whois.query.query.Query;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.annotation.CheckForNull;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

@Component
public class VersionQueryExecutor implements QueryExecutor {
    private final VersionDao versionDao;
    private final VersionResponseDecorator versionResponseDecorator;
    private final static String VERSION_HEADER = "rev#";
    private final static String DATE_HEADER = "Date";
    private final static String OPERATION_HEADER = "Op.";

    @Autowired
    public VersionQueryExecutor(final VersionResponseDecorator versionResponseDecorator, final VersionDao versionDao) {
        this.versionResponseDecorator = versionResponseDecorator;
        this.versionDao = versionDao;
    }

    @Override
    public boolean isAclSupported() {
        return false;
    }

    @Override
    public boolean supports(final Query query) {
        return query.isVersionList() || query.isObjectVersion();
    }

    @Override
    public void execute(final Query query, final ResponseHandler responseHandler) {
        final Iterable<? extends ResponseObject> responseObjects = query.isVersionList() ? getAllVersions(query) : getVersion(query);

        // TODO: [AH] refactor this spaghetti
        for (final ResponseObject responseObject : versionResponseDecorator.getResponse(responseObjects)) {
            if (query.isObjectVersion() && responseObject instanceof RpslObject) {
                final VersionWithRpslResponseObject withVersion = new VersionWithRpslResponseObject((RpslObject) responseObject, query.getObjectVersion());
                responseHandler.handle(withVersion);
            } else {
                responseHandler.handle(responseObject);
            }
        }
    }

    private Iterable<? extends ResponseObject> getAllVersions(final Query query) {
        VersionLookupResult res = getVersionInfo(query);

        if (res == null) {
            return Collections.emptyList();
        }

        final ObjectType objectType = res.getObjectType();

        if (objectType == ObjectType.PERSON || objectType == ObjectType.ROLE) {
            return Collections.singletonList(new MessageObject(QueryMessages.versionPersonRole(objectType.getName().toUpperCase(), query.getSearchValue())));
        }

        final List<ResponseObject> messages = Lists.newArrayList();
        messages.add(new MessageObject(QueryMessages.versionListHeader(objectType.getName().toUpperCase(), query.getCleanSearchValue())));

        final VersionDateTime lastDeletionTimestamp = res.getLastDeletionTimestamp();
        final String pkey = res.getPkey();
        if (lastDeletionTimestamp != null) {
            messages.add(new DeletedVersionResponseObject(lastDeletionTimestamp, objectType, pkey));
        }

        final List<VersionInfo> versionInfos = res.getVersionInfos();
        int versionPadding = getPadding(versionInfos);

        messages.add(new MessageObject(String.format("\n%-" + versionPadding + "s  %-16s  %-7s\n", VERSION_HEADER, DATE_HEADER, OPERATION_HEADER)));

        for (int i = 0; i < versionInfos.size(); i++) {
            final VersionInfo versionInfo = versionInfos.get(i);
            messages.add(new VersionResponseObject(versionPadding, versionInfo.getOperation(), i + 1, versionInfo.getTimestamp(), objectType, pkey));
        }

        messages.add(new MessageObject(""));

        return messages;
    }

    private int getPadding(List<VersionInfo> versionInfos) {
        // Minimum is the column header size
        int versionPadding = String.valueOf(versionInfos.size()).length();
        if (versionPadding < VERSION_HEADER.length()) {
            versionPadding = VERSION_HEADER.length();
        }
        return versionPadding;
    }

    private Iterable<? extends ResponseObject> getVersion(final Query query) {
        VersionLookupResult res = getVersionInfo(query);
        if (res == null) {
            return Collections.emptyList();
        }

        final List<VersionInfo> versionInfos = res.getVersionInfos();
        final int version = query.getObjectVersion();

        final VersionDateTime lastDeletionTimestamp = res.getLastDeletionTimestamp();
        if (versionInfos.isEmpty() && lastDeletionTimestamp != null) {
            return Collections.singletonList(new MessageObject(QueryMessages.versionDeleted(lastDeletionTimestamp.toString())));
        }

        if (version < 1 || version > versionInfos.size()) {
            return Collections.singletonList(new MessageObject(QueryMessages.versionOutOfRange(versionInfos.size())));
        }

        final VersionInfo info = versionInfos.get(version - 1);
        final RpslObject rpslObject = versionDao.getRpslObject(info);

        if (rpslObject.getType() == ObjectType.PERSON || rpslObject.getType() == ObjectType.ROLE) {
            return Collections.singletonList(new MessageObject(QueryMessages.versionPersonRole(rpslObject.getType().getName().toUpperCase(), query.getSearchValue())));
        }

        return Lists.newArrayList(
                new MessageObject(QueryMessages.versionInformation(version, (version == versionInfos.size()), rpslObject.getKey(), info.getOperation(), info.getTimestamp())),
                rpslObject);
    }

    private Collection<ObjectType> getObjectType(final Query query) {
        if (query.hasObjectTypesSpecified()) {
            return query.getObjectTypes();
        }

        return versionDao.getObjectType(query.getCleanSearchValue());
    }

    @CheckForNull
    public VersionLookupResult getVersionInfo(final Query query) {
        for (ObjectType type : getObjectType(query)) {
            final VersionLookupResult found = versionDao.findByKey(type, query.getCleanSearchValue());
            if (found != null) {
                return found;
            }
        }

        return null;
    }
}
