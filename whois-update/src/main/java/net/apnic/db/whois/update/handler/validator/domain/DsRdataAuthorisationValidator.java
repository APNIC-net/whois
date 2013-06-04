package net.apnic.db.whois.update.handler.validator.domain;

import com.google.common.collect.Lists;
import net.ripe.db.whois.common.domain.CIString;
import net.ripe.db.whois.common.profiles.WhoisVariantContext;
import net.ripe.db.whois.common.profiles.WhoisVariant;
import net.ripe.db.whois.common.rpsl.AttributeType;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.update.domain.Action;
import net.ripe.db.whois.update.domain.Origin;
import net.ripe.db.whois.update.domain.PreparedUpdate;
import net.ripe.db.whois.update.domain.UpdateContext;
import net.ripe.db.whois.update.domain.UpdateMessages;
import net.ripe.db.whois.update.handler.validator.BusinessRuleValidator;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Set;

@WhoisVariantContext(includeWhen = WhoisVariant.Type.APNIC)
@Component
public class DsRdataAuthorisationValidator implements BusinessRuleValidator {
    @Override
    public List<Action> getActions() {
        return Lists.newArrayList(Action.CREATE, Action.MODIFY, Action.DELETE);
    }

    @Override
    public List<ObjectType> getTypes() {
        return Lists.newArrayList(ObjectType.DOMAIN);
    }

    @Override
    public void validate(final PreparedUpdate update, final UpdateContext updateContext) {
        if (update.isOverride()) {
            return;
        }
        if (update.getOrigin().getType().equals(Origin.Type.EMAIL_UPDATE)) {

            // If there is a difference in the ds-rdata then reject update
            Set<CIString> differences = update.getDifferences(AttributeType.DS_RDATA);
            if (differences != null && differences.size() > 0 ) {
                updateContext.addMessage(update, UpdateMessages.attributeDsRdataCannotBeModified());
            }
        }
    }
}
