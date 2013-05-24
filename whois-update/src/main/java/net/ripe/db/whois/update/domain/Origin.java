package net.ripe.db.whois.update.domain;

public interface Origin {
    boolean isDefaultOverride();

    boolean allowRipeOperations();

    String getId();

    String getFrom();

    String getResponseHeader();

    String getNotificationHeader();

    String getName();

    Type getType();

    enum Type {
        EMAIL_UPDATE("email update"),
        MAINTENANCE_JOB("maintenance job"),
        REST_API("rest api"),
        SYNC_UPDATE("sync update"),
        NOT_SPECIFIED("not specified");

        private String name;

        private Type(String name) {
            this.name = name;
        }

        public String getName() {
            return name;
        }
    }
}
