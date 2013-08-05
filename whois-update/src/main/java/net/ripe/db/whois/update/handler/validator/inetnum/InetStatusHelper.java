package net.ripe.db.whois.update.handler.validator.inetnum;

import net.ripe.db.whois.common.domain.CIString;
import net.ripe.db.whois.common.domain.attrs.InetStatus;
import net.ripe.db.whois.common.profiles.WhoisVariant;
import net.ripe.db.whois.common.rpsl.AttributeType;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.RpslObject;
import net.ripe.db.whois.update.domain.PreparedUpdate;

import javax.annotation.CheckForNull;

public class InetStatusHelper {
    private InetStatusHelper() {
    }

    public static InetStatus getStatus(final PreparedUpdate update) {
        return getStatus(update.getUpdatedObject().getValueForAttribute(AttributeType.STATUS), update);
    }

    public static InetStatus getStatus(final RpslObject update) {
        return getStatus(update.getValueForAttribute(AttributeType.STATUS), update);
    }

    @CheckForNull
    public static InetStatus getStatus(final CIString value, final PreparedUpdate update) {
        return getStatus(value, update.getType());
    }

    @CheckForNull
    public static InetStatus getStatus(final CIString value, final RpslObject update) {
        return getStatus(value, update.getType());
    }

    @CheckForNull
    private static InetStatus getStatus(final CIString value, final ObjectType objectType) {
        switch (objectType) {
            case INETNUM:
                try {
                    return WhoisVariant.isAPNIC()
                            ? net.apnic.db.whois.common.domain.attrs.InetnumStatus.getStatusFor(value)
                            : net.ripe.db.whois.common.domain.attrs.InetnumStatus.getStatusFor(value);
                } catch (IllegalArgumentException ignored) {
                }
            case INET6NUM:
                try {
                    return WhoisVariant.isAPNIC()
                            ? net.apnic.db.whois.common.domain.attrs.Inet6numStatus.getStatusFor(value)
                            : net.ripe.db.whois.common.domain.attrs.Inet6numStatus.getStatusFor(value);
                } catch (IllegalArgumentException ignored) {
                }
        }

        return null;
    }
}
