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
                exception.getDescription().add("The request could not be understood by the server due to malformed syntax.");
                break;
            case 403:
                exception.getDescription().add("Authorization required.");
                break;
            case 404:
                exception.getDescription().add("The server has not found anything matching the Request-URI.");
                break;
            case 429:
                exception.getDescription().add("Request limit exceeded for this resource. Please try again later.");
                break;
            case 500:
                exception.getDescription().add("The server encountered an unexpected condition which prevented it from fulfilling the request.");
                break;

        }
        return exception;
    }
}
