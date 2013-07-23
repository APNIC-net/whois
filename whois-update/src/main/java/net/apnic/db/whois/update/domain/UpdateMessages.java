package net.apnic.db.whois.update.domain;

import com.google.common.base.Joiner;
import net.ripe.db.whois.common.Message;
import net.ripe.db.whois.common.domain.CIString;

import static net.ripe.db.whois.common.FormatHelper.prettyPrint;
import static net.ripe.db.whois.common.Messages.Type;

public final class UpdateMessages {
    private static final Joiner LIST_JOINED = Joiner.on(", ");

    public static String print(final Message message) {
        return prettyPrint(String.format("***%s: ", message.getType()), message.getValue(), 12, 80);
    }

    private UpdateMessages() {
    }

    public static Message portableStatusRequiresAllocMaintainer() {
        return new Message(Type.ERROR, "PORTABLE inetnum objects require an NIR maintainer");
    }

    public static Message invalidParentStatus(CIString key, String allowedParentInetStatusMessage) {
        return new Message(Type.ERROR, "Parent %s does not have status:\n        %s", key, allowedParentInetStatusMessage);
    }

    public static Message hasNoParents(String objectType, CIString key) {
        return new Message(Type.ERROR, "%s %s has no parents", objectType, key);
    }
}
