package net.ripe.db.whois.update.domain;

import net.ripe.db.whois.common.rpsl.RpslObjectBase;
import org.joda.time.LocalDateTime;

import javax.annotation.concurrent.Immutable;
import java.util.Set;

@Immutable
public class PendingUpdate {
    final Set<String> passedAuthentications;
    final RpslObjectBase object;
    LocalDateTime storedDate;
    long id;

    public PendingUpdate(final Set<String> passedAuthentications, final RpslObjectBase object) {
        this.passedAuthentications = passedAuthentications;
        this.object = object;
        this.storedDate = new LocalDateTime();
        this.id = 0;
    }

    public PendingUpdate(final long id, final Set<String> passedAuthentications, final RpslObjectBase object, final LocalDateTime storedDate) {
        this(passedAuthentications, object);
        this.storedDate = storedDate;
        this.id = id;
    }

    public long getId() {
        return id;
    }

    public Set<String> getPassedAuthentications() {
        return passedAuthentications;
    }

    public RpslObjectBase getObject() {
        return object;
    }

    public LocalDateTime getStoredDate() {
        return storedDate;
    }
}
