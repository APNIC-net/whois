package net.ripe.db.whois.update.handler;

import com.google.common.collect.Maps;
import net.ripe.db.whois.common.dao.RpslObjectDao;
import net.ripe.db.whois.common.dao.VersionDao;
import net.ripe.db.whois.common.dao.VersionLookupResult;
import net.ripe.db.whois.common.domain.CIString;
import net.ripe.db.whois.common.rpsl.AttributeType;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.RpslObject;
import net.ripe.db.whois.update.domain.*;
import net.ripe.db.whois.update.handler.response.ResponseFactory;
import net.ripe.db.whois.update.mail.MailGateway;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Collections;
import java.util.Map;

@Component
public class UpdateNotifier {
    private static final Logger LOGGER = LoggerFactory.getLogger(UpdateNotifier.class);

    private final RpslObjectDao rpslObjectDao;
    private final ResponseFactory responseFactory;
    private final MailGateway mailGateway;
    private final VersionDao versionDao;

    @Autowired
    public UpdateNotifier(final RpslObjectDao rpslObjectDao, final ResponseFactory responseFactory, final MailGateway mailGateway, final VersionDao versionDao) {
        this.rpslObjectDao = rpslObjectDao;
        this.responseFactory = responseFactory;
        this.mailGateway = mailGateway;
        this.versionDao = versionDao;
    }

    public void sendNotifications(final UpdateRequest updateRequest, final UpdateContext updateContext) {
        final Map<CIString, Notification> notifications = Maps.newHashMap();

        for (final Update update : updateRequest.getUpdates()) {
            final PreparedUpdate preparedUpdate = updateContext.getPreparedUpdate(update);
            if (preparedUpdate != null && !notificationsDisabledByOverride(preparedUpdate)) {
                addVersionId(preparedUpdate, updateContext);
                addNotifications(notifications, preparedUpdate, updateContext);
            }
        }

        for (final Notification notification : notifications.values()) {
            final ResponseMessage responseMessage = responseFactory.createNotification(updateContext, updateRequest.getOrigin(), notification);
            mailGateway.sendEmail(notification.getEmail(), responseMessage);
        }
    }

    private void addVersionId(PreparedUpdate preparedUpdate, UpdateContext context) {
        if (preparedUpdate.getAction() != Action.MODIFY) {
            return;
        }

        VersionLookupResult res = versionDao.findByKey(preparedUpdate.getType(), preparedUpdate.getKey());
        if (res == null) {
            LOGGER.info("Failed to find version lookup result on update for " + preparedUpdate.toString());
        } else {
            final int versionId = res.getVersionIdFor(context.getUpdateInfo(preparedUpdate)) - 1;   // -1 as we want the previous version
            context.versionId(preparedUpdate, versionId);
        }
    }

    private boolean notificationsDisabledByOverride(PreparedUpdate preparedUpdate) {
        final OverrideOptions overrideOptions = preparedUpdate.getOverrideOptions();
        return overrideOptions.isNotifyOverride() && !overrideOptions.isNotify();
    }

    private void addNotifications(final Map<CIString, Notification> notifications, final PreparedUpdate update, final UpdateContext updateContext) {
        final RpslObject object = update.getReferenceObject();

        switch (updateContext.getStatus(update)) {
            case SUCCESS:
                add(notifications, updateContext, update, Notification.Type.SUCCESS, Collections.singletonList(object), AttributeType.NOTIFY);
                add(notifications, updateContext, update, Notification.Type.SUCCESS, rpslObjectDao.getByKeys(ObjectType.MNTNER, object.getValuesForAttribute(AttributeType.MNT_BY)), AttributeType.MNT_NFY);
                add(notifications, updateContext, update, Notification.Type.SUCCESS_REFERENCE, rpslObjectDao.getByKeys(ObjectType.ORGANISATION, update.getDifferences(AttributeType.ORG)), AttributeType.REF_NFY);
                add(notifications, updateContext, update, Notification.Type.SUCCESS_REFERENCE, rpslObjectDao.getByKeys(ObjectType.IRT, update.getDifferences(AttributeType.MNT_IRT)), AttributeType.IRT_NFY);
                break;

            case FAILED_AUTHENTICATION:
                add(notifications, updateContext, update, Notification.Type.FAILED_AUTHENTICATION, rpslObjectDao.getByKeys(ObjectType.MNTNER, object.getValuesForAttribute(AttributeType.MNT_BY)), AttributeType.UPD_TO);
                break;

            case PENDING_AUTHENTICATION:
                add(notifications, updateContext, update, Notification.Type.PENDING_UPDATE, updateContext.getSubject(update).getPendingAuthenticationCandidates(), AttributeType.UPD_TO);
                break;

            default:
                break;
        }
    }

    private void add(final Map<CIString, Notification> notifications, UpdateContext updateContext, final PreparedUpdate update, final Notification.Type type, final Iterable<RpslObject> objects, final AttributeType attributeType) {
        for (final RpslObject object : objects) {
            for (final CIString email : object.getValuesForAttribute(attributeType)) {
                Notification notification = notifications.get(email);
                if (notification == null) {
                    notification = new Notification(email.toString());
                    notifications.put(email, notification);
                }

                notification.add(type, update, updateContext);
            }
        }
    }
}
