package net.ripe.db.whois.api.whois.rdap;

import com.google.common.collect.Lists;
import net.ripe.db.whois.api.whois.rdap.domain.Error;
import net.ripe.db.whois.api.whois.rdap.NoticeFactory;
import org.springframework.beans.factory.annotation.Autowired;

import javax.ws.rs.core.Response;
import java.util.List;

public class RdapException {
    private static String statusCodeToString(int statusCode) {
        String statusString = null;
        switch (statusCode) {
            case 400:
                statusString = "The request could not be understood by the server due to malformed syntax.";
                break;
            case 403:
                statusString = "Authorization required.";
                break;
            case 404:
                statusString = "The server has not found anything matching the Request-URI.";
                break;
            case 429:
                statusString = "Request limit exceeded for this resource. Please try again later.";
                break;
            default:
                statusString = "The server encountered an unexpected condition which prevented it from fulfilling the request.";
                break;
        }
        return statusString;
    }

    public static Object build (final Response.StatusType status, final String selfUrl, final NoticeFactory noticeFactory) {
        return build(status, selfUrl, Lists.<String>newArrayList(), noticeFactory, false);
    }

    public static Object build (final Response.StatusType status, final String selfUrl, List<String> descriptions, final NoticeFactory noticeFactory, boolean suppressDefaultDescription) {
        return build(status.getStatusCode(), status.getReasonPhrase(), selfUrl, descriptions, noticeFactory, suppressDefaultDescription);
    }

    public static Object build (final int statusCode, final String reasonPhrase, final String selfUrl, List<String> descriptions, final NoticeFactory noticeFactory, boolean suppressDefaultDescription) {
        final Error exception = new Error();
        exception.setErrorCode(statusCode);
        exception.setTitle(reasonPhrase);
        exception.getRdapConformance().addAll(RdapObjectMapper.RDAP_CONFORMANCE_LEVEL);
        /* todo: This shouldn't be null. The check should only be here temporarily. */
        if (noticeFactory != null) {
            exception.getNotices().addAll(noticeFactory.generateResponseNotices(selfUrl));
        }

        if (!suppressDefaultDescription) {
            exception.getDescription().add(statusCodeToString(statusCode));
        }
        exception.getDescription().addAll(descriptions);
        return exception;
    }
}
