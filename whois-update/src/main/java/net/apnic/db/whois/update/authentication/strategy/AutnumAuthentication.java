package net.apnic.db.whois.update.authentication.strategy;


import net.ripe.db.whois.common.dao.RpslObjectDao;
import net.ripe.db.whois.common.domain.CIString;
import net.ripe.db.whois.common.profiles.WhoisVariant;
import net.ripe.db.whois.common.profiles.WhoisVariantContext;
import net.ripe.db.whois.common.rpsl.AttributeType;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.RpslObject;
import net.ripe.db.whois.update.authentication.credential.AuthenticationModule;
import net.ripe.db.whois.update.authentication.strategy.AuthenticationFailedException;
import net.ripe.db.whois.update.authentication.strategy.AuthenticationStrategy;
import net.ripe.db.whois.update.domain.Action;
import net.ripe.db.whois.update.domain.PreparedUpdate;
import net.ripe.db.whois.update.domain.UpdateContext;
import net.ripe.db.whois.update.domain.UpdateMessages;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Set;

@WhoisVariantContext(includeWhen = WhoisVariant.Type.APNIC)
@Component
public class AutnumAuthentication implements AuthenticationStrategy {
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
    public Set<ObjectType> getPendingAuthenticationTypes() {
        return Collections.emptySet();
    }

    // @TODO: Customise as per SCRUM-1549
    @Override
    public List<RpslObject> authenticate(final PreparedUpdate update, final UpdateContext updateContext) {
        final RpslObject object = update.getUpdatedObject();

        final CIString pkey = object.getKey();
        final long number = Long.parseLong(pkey.toString().substring("AS".length()));
        final RpslObject asBlock = objectDao.findAsBlock(number, number);
        if (asBlock == null) {
            throw new AuthenticationFailedException(UpdateMessages.noParentAsBlockFound(pkey));
        }

        AttributeType attributeType = AttributeType.MNT_LOWER;
        Collection<CIString> parentMnts = asBlock.getValuesForAttribute(attributeType);
        if (parentMnts.isEmpty()) {
            attributeType = AttributeType.MNT_BY;
            parentMnts = asBlock.getValuesForAttribute(attributeType);
        }

        final List<RpslObject> maintainers = objectDao.getByKeys(ObjectType.MNTNER, parentMnts);
        final List<RpslObject> authenticatedBy = authenticationModule.authenticate(update, updateContext, maintainers);
        if (authenticatedBy.isEmpty()) {
            throw new AuthenticationFailedException(UpdateMessages.authenticationFailed(asBlock, attributeType, maintainers));
        }
        return authenticatedBy;
    }
}
