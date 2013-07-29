package net.ripe.db.whois.query.domain;

import com.google.common.collect.Maps;
import org.springframework.beans.factory.BeanInitializationException;

import java.util.Map;

public final class QueryMessagesMap {

    static Map<QueryMessages.QueryMessageType, String> queryMessages = Maps.newHashMap();

    static {
        put(QueryMessages.QueryMessageType.TERMS_AND_CONDITIONS, ""
                + "% This is the RIPE Database query service.\n"
                + "% The objects are in RPSL format.\n"
                + "%\n"
                + "% The RIPE Database is subject to Terms and Conditions.\n"
                + "% See http://www.ripe.net/db/support/db-terms-conditions.pdf\n");

        put(QueryMessages.QueryMessageType.TERMS_AND_CONDITIONS_DUMP, "" +
                "#\n" +
                "# The contents of this file are subject to \n" +
                "# RIPE Database Terms and Conditions\n" +
                "#\n" +
                "# http://www.ripe.net/db/support/db-terms-conditions.pdf\n" +
                "#\n");

        put(QueryMessages.QueryMessageType.SERVED_BY_NOTICE, "" +
                "%% This query was served by the RIPE Database Query Service version %s (%s)\n");

        put(QueryMessages.QueryMessageType.INTERNAL_ERROR_OCCURED, ""
                + "%ERROR:100: internal software error\n"
                + "%\n"
                + "% Please contact ripe-dbm@ripe.net if the problem persists.\n");

        put(QueryMessages.QueryMessageType.ILLEGAL_RANGE, ""
                + "%ERROR:112: unsupported query\n"
                + "%\n"
                + "% '-mM' query options are not allowed on very large ranges/prefixes.\n"
                + "% This data is available from the daily object split files:\n"
                + "% ftp://ftp.ripe.net/ripe/dbase/split/\n");

        put(QueryMessages.QueryMessageType.ACCESS_DENIED_PERMANENTLY, ""
                + "%%ERROR:201: access denied for %s\n"
                + "%%\n"
                + "%% Sorry, access from your host has been permanently\n"
                + "%% denied because of a repeated excessive querying.\n"
                + "%% For more information, see\n"
                + "%% http://www.ripe.net/data-tools/db/faq/faq-db/why-did-you-receive-the-error-201-access-denied\n");

        put(QueryMessages.QueryMessageType.ACCESS_DENIED_TEMPORARILY, ""
                + "%%ERROR:201: access denied for %s\n"
                + "%%\n"
                + "%% Queries from your IP address have passed the daily limit of controlled objects.\n"
                + "%% Access from your host has been temporarily denied.\n"
                + "%% For more information, see\n"
                + "%% http://www.ripe.net/data-tools/db/faq/faq-db/why-did-you-receive-the-error-201-access-denied\n");

        put(QueryMessages.QueryMessageType.TIMEOUT, ""
                + "%ERROR:305: connection has been closed\n"
                + "%\n"
                + "% The connection to the RIPE Database query server\n"
                + "% has been closed after a period of inactivity.\n");


    }

    private QueryMessagesMap() {
    }

    public static Map<QueryMessages.QueryMessageType, String> getQueryMessagesMap() {
        return queryMessages;
    }

    private static void put(QueryMessages.QueryMessageType type, String value) {
        // Test for duplicates
        if (queryMessages.put(type, value) != null) {
            throw new BeanInitializationException("Query Messages duplicate mapping exception: " + type);
        }
    }

}
