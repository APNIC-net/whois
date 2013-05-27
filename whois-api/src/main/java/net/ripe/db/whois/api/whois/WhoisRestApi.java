package net.ripe.db.whois.api.whois;

import net.ripe.db.whois.common.DateTimeProvider;
import net.ripe.db.whois.update.domain.Origin;
import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;

public class WhoisRestApi implements Origin {
    private static final DateTimeFormatter DATE_FORMAT = DateTimeFormat.forPattern("E MMM d HH:mm:ss yyyy");

    private final DateTimeProvider dateTimeProvider;
    private final String remoteAddress;

    public WhoisRestApi(final DateTimeProvider dateTimeProvider, final String remoteAddress) {
        this.remoteAddress = remoteAddress;
        this.dateTimeProvider = dateTimeProvider;
    }

    @Override
    public boolean isDefaultOverride() {
        return false;
    }

    @Override
    public boolean allowRipeOperations() {
        return false;
    }

    @Override
    public String getId() {
        return remoteAddress;
    }

    @Override
    public String getFrom() {
        return remoteAddress;
    }

    @Override
    public String getResponseHeader() {
        return getHeader();
    }

    @Override
    public String getNotificationHeader() {
        return getHeader();
    }

    private String getHeader() {
        return String.format("" +
                " - From-Host: %s\n" +
                " - Date/Time: %s\n",
                remoteAddress,
                DATE_FORMAT.print(dateTimeProvider.getCurrentDateTime()));
    }

    @Override
    public String getName() {
        return getType().getName();
    }

    @Override
    public Type getType() {
        return Type.REST_API;
    }

    @Override
    public String toString() {
        return "SyncUpdate(" + getId() + ")";
    }
}
