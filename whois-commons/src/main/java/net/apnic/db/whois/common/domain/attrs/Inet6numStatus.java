package net.apnic.db.whois.common.domain.attrs;

import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import net.ripe.db.whois.common.domain.CIString;
import net.ripe.db.whois.common.domain.attrs.InetStatus;
import net.ripe.db.whois.common.domain.attrs.OrgType;

import java.util.Collections;
import java.util.Set;

import static net.ripe.db.whois.common.domain.CIString.ciString;

public enum Inet6numStatus implements InetStatus {

    ALLOCATED_PORTABLE("ALLOCATED PORTABLE"),
    ALLOCATED_NON_PORTABLE("ALLOCATED NON-PORTABLE"),
    ASSIGNED_PORTABLE("ASSIGNED PORTABLE"),
    ASSIGNED_NON_PORTABLE("ASSIGNED NON-PORTABLE");

    private static final Set<OrgType> allowedOrgTypes = Collections.unmodifiableSet(Sets.newEnumSet(Lists.<OrgType>newArrayList(), OrgType.class));

    private final CIString literalStatus;

    private Inet6numStatus(final String literalStatus) {
        this.literalStatus = ciString(literalStatus);
    }

    public static Inet6numStatus getStatusFor(final CIString status) {
        for (final Inet6numStatus stat : Inet6numStatus.values()) {
            if (stat.literalStatus.equals(status)) {
                return stat;
            }
        }

        throw new IllegalArgumentException(status + " is not a valid inet6numstatus");
    }

    public CIString getLiteralStatus() {
        return literalStatus;
    }

    // Not used
    @Override
    public boolean isValidOrgType(final OrgType orgType) {
        return true;
    }

    // Not used
    @Override
    public Set<OrgType> getAllowedOrgTypes() {
        return allowedOrgTypes;
    }

    // Not used
    @Override
    public boolean requiresRsMaintainer() {
        return false;
    }

    @Override
    public boolean requiresAllocMaintainer() {
        return literalStatus.endsWith(CIString.ciString(" PORTABLE"));
    }

    // Not used
    @Override
    public boolean worksWithParentStatus(final InetStatus parent, final boolean objectHasRsMaintainer) {
        return true;
    }

    // Not used
    @Override
    public boolean worksWithParentInHierarchy(final InetStatus parentInHierarchyMaintainedByRs, final boolean parentHasRsMntLower) {
        return true;
    }

    @Override
    public boolean needsOrgReference() {
        return false;
    }

    @Override
    public String toString() {
        return literalStatus.toString();
    }
}
