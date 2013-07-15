package net.ripe.db.whois.api.whois.rdap;

import net.ripe.db.whois.api.whois.rdap.domain.Error;

public class RdapException {

    public static Object build (final int status) {
        final Error exception = new Error();
        exception.setErrorCode(status);

        switch (status) {
            case 400:
                exception.setTitle("Bad request");
                exception.getDescription().add("These are not the droids you are looking for.");
                break;
            case 403:
                exception.setTitle("Forbidden");
                exception.getDescription().add("You're a part of the Rebel Alliance and a traitor.");
                exception.getDescription().add("Take her away!");
                break;
            case 404:
                exception.setTitle("Not found");
                exception.getDescription().add("What a desolate place this is.");
                break;
            case 429:
                exception.setTitle("Too many requests");
                exception.getDescription().add("I can't shake em!");
                exception.getDescription().add("I can't shake em!");
                break;
            case 500:
                exception.setTitle("Internal server error");
                exception.getDescription().add("I felt a great disturbance in the Force...");
                exception.getDescription().add("As if millions of voices cried out in terror and were suddenly silenced.");
                exception.getDescription().add("I fear something terrible has happened.");
                break;

        }
        return exception;
    }
}
