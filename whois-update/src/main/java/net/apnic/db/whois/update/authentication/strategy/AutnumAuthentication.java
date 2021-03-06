package net.apnic.db.whois.update.authentication.strategy;

import com.google.common.collect.Lists;
import com.google.common.collect.Sets;
import net.ripe.db.whois.common.Message;
import net.ripe.db.whois.common.dao.RpslObjectDao;
import net.ripe.db.whois.common.domain.CIString;
import net.ripe.db.whois.common.profiles.WhoisVariant;
import net.ripe.db.whois.common.profiles.WhoisVariantContext;
import net.ripe.db.whois.common.rpsl.AttributeType;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.RpslObject;
import net.ripe.db.whois.update.authentication.credential.AuthenticationModule;
import net.ripe.db.whois.update.authentication.strategy.AuthenticationFailedException;
import net.ripe.db.whois.update.authentication.strategy.AuthenticationStrategyBase;
import net.ripe.db.whois.update.domain.Action;
import net.ripe.db.whois.update.domain.PreparedUpdate;
import net.ripe.db.whois.update.domain.UpdateContext;
import net.ripe.db.whois.update.domain.UpdateMessages;
import org.apache.commons.collections.CollectionUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Set;

@WhoisVariantContext(includeWhen = WhoisVariant.Type.APNIC)
@Component
public class AutnumAuthentication extends AuthenticationStrategyBase {
    private final RpslObjectDao objectDao;
    private final AuthenticationModule authenticationModule;

    @Autowired
    public AutnumAuthentication(final RpslObjectDao objectDao, final AuthenticationModule authenticationModule) {
        this.objectDao = objectDao;
        this.authenticationModule = authenticationModule;
    }

    @Override
    public boolean supports(final PreparedUpdate update) {
        return update.getType().equals(ObjectType.AUT_NUM) && update.getAction().equals(Action.CREATE);
    }

    @Override
    public List<RpslObject> authenticate(final PreparedUpdate update, final UpdateContext updateContext) {
        final RpslObject object = update.getUpdatedObject();

        final CIString pkey = object.getKey();
        final long number = Long.parseLong(pkey.toString().substring("AS".length()));

        List<RpslObject> asBlockList = objectDao.findAsBlockIntersections(number, number);
        if (CollectionUtils.isEmpty(asBlockList)) {
            throw new AuthenticationFailedException(UpdateMessages.noParentAsBlockFound(pkey), Collections.<RpslObject>emptyList());
        }

        List<Message> authenticationErrorMessages = Lists.newArrayList();

        final Set<RpslObject> authenticatedBy = Sets.newHashSet();
        for (RpslObject asBlock : asBlockList) {
            AttributeType attributeType = AttributeType.MNT_LOWER;
            Collection<CIString> parentMnts = asBlock.getValuesForAttribute(attributeType);
            if (parentMnts.isEmpty()) {
                attributeType = AttributeType.MNT_BY;
                parentMnts = asBlock.getValuesForAttribute(attributeType);
            }

            final List<RpslObject> maintainers = objectDao.getByKeys(ObjectType.MNTNER, parentMnts);
            final List<RpslObject> authenticatedByEntry = authenticationModule.authenticate(update, updateContext, maintainers);
            if (!authenticatedByEntry.isEmpty()) {
                authenticatedBy.addAll(authenticatedByEntry);
            } else {
                authenticationErrorMessages.add(UpdateMessages.authenticationFailed(asBlock, attributeType, maintainers));
            }
        }

        if (authenticatedBy.isEmpty()) {
            throw new AuthenticationFailedException(authenticationErrorMessages, Collections.<RpslObject>emptyList());
        }

        return Lists.newArrayList(authenticatedBy);
    }
}
