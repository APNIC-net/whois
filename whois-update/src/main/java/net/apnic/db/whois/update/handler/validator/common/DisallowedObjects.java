package net.apnic.db.whois.update.handler.validator.common;

import com.google.common.collect.Lists;
import net.ripe.db.whois.common.profiles.WhoisVariant;
import net.ripe.db.whois.common.profiles.WhoisVariantContext;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.update.domain.Action;
import net.ripe.db.whois.update.domain.PreparedUpdate;
import net.ripe.db.whois.update.domain.UpdateContext;
import net.ripe.db.whois.update.domain.UpdateMessages;
import net.ripe.db.whois.update.handler.validator.BusinessRuleValidator;
import org.springframework.stereotype.Component;

import java.util.List;

@WhoisVariantContext(includeWhen = WhoisVariant.Type.APNIC)
@Component
public class DisallowedObjects implements BusinessRuleValidator {
    @Override
    public List<Action> getActions() {
        return Lists.newArrayList(Action.CREATE, Action.MODIFY, Action.DELETE);
    }

    @Override
    public List<ObjectType> getTypes() {
        return Lists.newArrayList(ObjectType.POEM, ObjectType.POETIC_FORM);
    }

    @Override
    public void validate(final PreparedUpdate update, final UpdateContext updateContext) {
        updateContext.addMessage(update, UpdateMessages.objectNotAllowed(update.getType()));
    }
}
