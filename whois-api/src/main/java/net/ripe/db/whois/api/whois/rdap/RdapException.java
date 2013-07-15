package net.ripe.db.whois.api.whois.rdap;

import net.ripe.db.whois.api.whois.rdap.domain.Error;

import javax.ws.rs.core.Response;

public class RdapException {

    public static Object build (final Response.Status status) {
        final Error exception = new Error();
        exception.setErrorCode(status.getStatusCode());
        exception.setTitle(status.getReasonPhrase());

        switch (status.getStatusCode()) {
            case 400:
                exception.getDescription().add("These are not the droids you are looking for.");
                break;
            case 403:
                exception.getDescription().add("You're a part of the Rebel Alliance and a traitor.");
                exception.getDescription().add("Take her away!");
                break;
            case 404:
                exception.getDescription().add("What a desolate place this is.");
                break;
            case 429:
                exception.getDescription().add("I can't shake em!");
                exception.getDescription().add("I can't shake em!");
                break;
            case 500:
                exception.getDescription().add("I felt a great disturbance in the Force...");
                exception.getDescription().add("As if millions of voices cried out in terror and were suddenly silenced.");
                exception.getDescription().add("I fear something terrible has happened.");
                break;

        }
        return exception;
    }
}
