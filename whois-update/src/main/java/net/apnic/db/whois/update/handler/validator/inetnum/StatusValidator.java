package net.apnic.db.whois.update.handler.validator.inetnum;

import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import net.apnic.db.whois.common.domain.attrs.Inet6numStatus;
import net.apnic.db.whois.common.domain.attrs.InetnumStatus;
import net.ripe.db.whois.common.Message;
import net.ripe.db.whois.common.dao.RpslObjectDao;
import net.ripe.db.whois.common.domain.*;
import net.ripe.db.whois.common.domain.attrs.InetStatus;
import net.ripe.db.whois.common.iptree.IpEntry;
import net.ripe.db.whois.common.iptree.IpTree;
import net.ripe.db.whois.common.iptree.Ipv4Tree;
import net.ripe.db.whois.common.iptree.Ipv6Tree;
import net.ripe.db.whois.common.profiles.WhoisVariant;
import net.ripe.db.whois.common.profiles.WhoisVariantContext;
import net.ripe.db.whois.common.rpsl.AttributeType;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.RpslAttribute;
import net.ripe.db.whois.common.rpsl.RpslObject;
import net.ripe.db.whois.update.domain.Action;
import net.ripe.db.whois.update.domain.PreparedUpdate;
import net.ripe.db.whois.update.domain.UpdateContext;
import net.ripe.db.whois.update.domain.UpdateMessages;
import net.ripe.db.whois.update.handler.validator.BusinessRuleValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.annotation.CheckForNull;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import static net.apnic.db.whois.update.handler.validator.inetnum.InetStatusHelper.getStatus;

@WhoisVariantContext(includeWhen = WhoisVariant.Type.APNIC)
@Component
public class StatusValidator implements BusinessRuleValidator {

    private static final Set<InetnumStatus> allowedParentInetStatuses = Collections.unmodifiableSet(
            Sets.newHashSet(InetnumStatus.ALLOCATED_NON_PORTABLE, InetnumStatus.ALLOCATED_PORTABLE)
    );
    private static final Set<Inet6numStatus> allowedParentInet6Statuses = Collections.unmodifiableSet(
            Sets.newHashSet(Inet6numStatus.ALLOCATED_NON_PORTABLE, Inet6numStatus.ALLOCATED_PORTABLE)
    );
    protected static String allowedParentInetStatusMessage = "";
    protected static String allowedParentInet6StatusMessage = "";

    static {
        for (InetnumStatus InetnumStatus : allowedParentInetStatuses) {
            allowedParentInetStatusMessage += "," + InetnumStatus.getLiteralStatus();
        }
        allowedParentInetStatusMessage = allowedParentInetStatusMessage.substring(1);

        for (Inet6numStatus Inetnum6Status : allowedParentInet6Statuses) {
            allowedParentInet6StatusMessage += "," + Inetnum6Status.getLiteralStatus();
        }
        allowedParentInet6StatusMessage = allowedParentInet6StatusMessage.substring(1);
    }

    private final RpslObjectDao objectDao;
    private final Ipv4Tree ipv4Tree;
    private final Ipv6Tree ipv6Tree;
    private final Maintainers maintainers;

    @Autowired
    public StatusValidator(
            final RpslObjectDao objectDao,
            final Ipv4Tree ipv4Tree,
            final Ipv6Tree ipv6Tree,
            final Maintainers maintainers) {
        this.objectDao = objectDao;
        this.ipv4Tree = ipv4Tree;
        this.ipv6Tree = ipv6Tree;
        this.maintainers = maintainers;

    }

    @Override
    public List<Action> getActions() {
        return Lists.newArrayList(Action.CREATE, Action.MODIFY, Action.DELETE);
    }

    @Override
    public List<ObjectType> getTypes() {
        return Lists.newArrayList(ObjectType.INETNUM, ObjectType.INET6NUM);
    }

    @Override
    public void validate(final PreparedUpdate update, final UpdateContext updateContext) {
        if (update.isOverride()) {
            return;
        }

        if (update.getAction().equals(Action.CREATE) || update.getAction().equals(Action.MODIFY)) {
            validateStatus(update, updateContext);
        }
    }

    private void validateStatus(final PreparedUpdate update, final UpdateContext updateContext) {
        final IpInterval ipInterval = IpInterval.parse(update.getUpdatedObject().getKey());
        final RpslObject updatedObject = update.getUpdatedObject();

// TODO: Not sure if we want to do this check. [Dragan]
//        if (!allChildrenHaveCorrectStatus(update, updateContext, ipTree, ipInterval)) {
//            return;
//        }

        final InetStatus currentStatus = InetStatusHelper.getStatus(update);
        if (currentStatus.requiresAllocMaintainer()) {
            checkAllocMaintainer(update, updateContext);
        } else {
            checkParentStatus(update, updateContext);
        }
    }

    private void checkAllocMaintainer(final PreparedUpdate update, final UpdateContext updateContext) {
        final RpslObject updatedObject = update.getUpdatedObject();
        final Set<CIString> mntBy = updatedObject.getValuesForAttribute(AttributeType.MNT_BY);

        if (Sets.intersection(maintainers.getAllocMaintainers(), mntBy).isEmpty()) {
            updateContext.addMessage(update, net.apnic.db.whois.update.domain.UpdateMessages.portableStatusRequiresAllocMaintainer());
            return;
        }
    }

    private void checkParentStatus(final PreparedUpdate update, final UpdateContext updateContext) {

        final IpInterval ipInterval = IpInterval.parse(update.getUpdatedObject().getKey());
        final List<IpEntry> parents = Lists.newArrayList();

        if (update.getType().equals(ObjectType.INETNUM)) {
            parents.addAll(ipv4Tree.findAllLessSpecific((Ipv4Resource) ipInterval));
        } else {
            parents.addAll(ipv6Tree.findAllLessSpecific((Ipv6Resource) ipInterval));
        }

        if (parents.isEmpty()) {
            updateContext.addMessage(update, net.apnic.db.whois.update.domain.UpdateMessages.hasNoParents(update.getType().getName(), update.getUpdatedObject().getKey()));
        } else {
            for (IpEntry parent : parents) {
                final RpslObject parentObject = objectDao.getById(parent.getObjectId());
                InetStatus parentStatus = InetStatusHelper.getStatus(parentObject);
                if (parentStatus instanceof InetnumStatus) {
                    if (!allowedParentInetStatuses.contains(parentStatus)) {
                        updateContext.addMessage(update, net.apnic.db.whois.update.domain.UpdateMessages.invalidParentStatus(parentObject.getKey(), allowedParentInetStatusMessage));
                    }
                } else {
                    if (!allowedParentInet6Statuses.contains(parentStatus)) {
                        updateContext.addMessage(update, net.apnic.db.whois.update.domain.UpdateMessages.invalidParentStatus(parentObject.getKey(), allowedParentInet6StatusMessage));
                    }
                }
            }
        }
    }

    @SuppressWarnings("unchecked")
    private boolean allChildrenHaveCorrectStatus(final PreparedUpdate update, final UpdateContext updateContext, final IpTree ipTree, final IpInterval ipInterval) {
        final List<IpEntry> children = ipTree.findFirstMoreSpecific(ipInterval);
        final RpslAttribute updateStatusAttribute = update.getUpdatedObject().findAttribute(AttributeType.STATUS);
        final InetStatus updatedStatus = InetStatusHelper.getStatus(update);

        for (final IpEntry child : children) {
            final RpslObject childObject = objectDao.getById(child.getObjectId());
            final List<RpslAttribute> childStatuses = childObject.findAttributes(AttributeType.STATUS);
            if (childStatuses.isEmpty()) {
                updateContext.addMessage(update, UpdateMessages.objectLacksStatus("Child", childObject.getKey()));
                continue;
            }

            final CIString childStatusValue = childStatuses.get(0).getCleanValue();
            final InetStatus childStatus = getStatus(childStatusValue, update);
            if (childStatus == null) {
                updateContext.addMessage(update, UpdateMessages.objectHasInvalidStatus("Child", childObject.getKey(), childStatusValue));
                return false;
            }
            final Set<CIString> childMntBy = childObject.getValuesForAttribute(AttributeType.MNT_BY);
            final boolean hasRsMaintainer = !Sets.intersection(maintainers.getRsMaintainers(), childMntBy).isEmpty();

            if (!childStatus.worksWithParentStatus(updatedStatus, hasRsMaintainer)) {
                updateContext.addMessage(update, UpdateMessages.incorrectChildStatus(updateStatusAttribute.getCleanValue(), childStatusValue));
                return false;
            } else if (updatedStatus.equals(InetnumStatus.ASSIGNED_PORTABLE) && childStatus.equals(InetnumStatus.ASSIGNED_PORTABLE)) {
                checkAuthorizationForStatusInHierarchy(update, updateContext, ipTree, ipInterval, UpdateMessages.incorrectChildStatus(updateStatusAttribute.getCleanValue(), childStatusValue));
            }
        }
        return true;
    }

    private void checkAuthorizationForStatusInHierarchy(final PreparedUpdate update, final UpdateContext updateContext, final IpTree ipTree, final IpInterval ipInterval, final Message errorMessage) {
        final RpslObject parentInHierarchyMaintainedByRs = findParentWithRsMaintainer(ipTree, ipInterval);

        if (parentInHierarchyMaintainedByRs != null) {

            final List<RpslAttribute> parentStatuses = parentInHierarchyMaintainedByRs.findAttributes(AttributeType.STATUS);
            if (parentStatuses.isEmpty()) {
                return;
            }

            final CIString parentStatusValue = parentStatuses.get(0).getCleanValue();
            final InetStatus parentStatus = net.apnic.db.whois.update.handler.validator.inetnum.InetStatusHelper.getStatus(parentStatusValue, update);

            if (parentStatus == null) {
                updateContext.addMessage(update, UpdateMessages.objectHasInvalidStatus("Parent", parentInHierarchyMaintainedByRs.getKey(), parentStatusValue));
            } else {
                final Set<CIString> mntLower = parentInHierarchyMaintainedByRs.getValuesForAttribute(AttributeType.MNT_LOWER);
                final boolean parentHasRsMntLower = !Sets.intersection(maintainers.getRsMaintainers(), mntLower).isEmpty();
                final InetStatus currentStatus = net.apnic.db.whois.update.handler.validator.inetnum.InetStatusHelper.getStatus(update);

                if (!currentStatus.worksWithParentInHierarchy(parentStatus, parentHasRsMntLower)) {
                    updateContext.addMessage(update, errorMessage);
                }
            }
        }
    }

    @CheckForNull
    private RpslObject findParentWithRsMaintainer(final IpTree ipTree, final IpInterval ipInterval) {
        @SuppressWarnings("unchecked")
        final List<IpEntry> allLessSpecific = Lists.reverse(ipTree.findAllLessSpecific(ipInterval));
        for (final IpEntry parent : allLessSpecific) {
            final RpslObject parentObject = objectDao.getById(parent.getObjectId());
            final Set<CIString> mntBy = parentObject.getValuesForAttribute(AttributeType.MNT_BY);

            final boolean missingRsMaintainer = Sets.intersection(maintainers.getRsMaintainers(), mntBy).isEmpty();
            if (!missingRsMaintainer) {
                return parentObject;
            }
        }

        return null;
    }

}
