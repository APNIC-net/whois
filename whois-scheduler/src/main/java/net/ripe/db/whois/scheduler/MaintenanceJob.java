package net.ripe.db.whois.scheduler;

import net.ripe.db.whois.update.domain.Origin;

public class MaintenanceJob implements Origin {
    private final String id;

    public MaintenanceJob(final String id) {
        this.id = id;
    }

    @Override
    public boolean isDefaultOverride() {
        return true;
    }

    @Override
    public boolean allowAdminOperations() {
        return true;
    }

    @Override
    public String getId() {
        return id;
    }

    @Override
    public String getFrom() {
        return id;
    }

    @Override
    public String getResponseHeader() {
        return "Maintenance job: " + getFrom() + "\n";
    }

    @Override
    public String getNotificationHeader() {
        return getResponseHeader();
    }

    @Override
    public String getName() {
        return getType().getName();
    }

    @Override
    public Type getType() {
        return Type.MAINTENANCE_JOB;
    }

    @Override
    public String toString() {
        return "MaintenanceJob(" + getId() + ")";
    }
}
