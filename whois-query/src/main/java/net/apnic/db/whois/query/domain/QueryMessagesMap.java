package net.apnic.db.whois.query.domain;

import com.google.common.collect.Maps;
import net.ripe.db.whois.query.domain.QueryMessages;
import org.springframework.beans.factory.BeanInitializationException;

import java.util.Map;

public final class QueryMessagesMap {

    static Map<QueryMessages.QueryMessageType, String> queryMessages = Maps.newHashMap();

    static {
        put(QueryMessages.QueryMessageType.TERMS_AND_CONDITIONS, ""
                + "% [whois.apnic.net]\n"
                + "% Whois data copyright terms    http://www.apnic.net/db/dbcopyright.html\n");


        put(QueryMessages.QueryMessageType.TERMS_AND_CONDITIONS_DUMP, ""
                + "#\n"
                + "# Copyright (c) 1994-1998 APNIC Ltd.\n"
                + "# Copyright (c) 1998-2010 APNIC Pty. Ltd.\n"
                + "#\n"
                + "# Restricted rights.\n"
                + "#\n"
                + "# Except for agreed Internet operational purposes, no part of this\n"
                + "# publication may be reproduced, stored in a retrieval system, or\n"
                + "# transmitted, in any form or by any means, electronic, mechanical,\n"
                + "# recording, or otherwise, without prior permission of APNIC on\n"
                + "# behalf of the copyright holders. Any use of this material to\n"
                + "# target advertising or similar activities are explicitly forbidden\n"
                + "# and will be prosecuted. APNIC requests to be notified of any such\n"
                + "# activities or suspicions thereof.\n"
                + "#\n");

        put(QueryMessages.QueryMessageType.SERVED_BY_NOTICE, "" +
                "%% This query was served by the APNIC Whois Service version %s (%s)\n");

        put(QueryMessages.QueryMessageType.INTERNAL_ERROR_OCCURED, ""
                + "%ERROR:100: internal software error\n"
                + "%\n"
                + "% Please contact <helpdesk@apnic.net> if the problem persists.\n");

        put(QueryMessages.QueryMessageType.ILLEGAL_RANGE, ""
                + "%ERROR:112: unsupported query\n"
                + "%\n"
                + "% '-mM' query options are not allowed on very large ranges/prefixes.\n"
                + "% This data is available from the daily object split files:\n"
                + "% ftp://ftp.apnic.net/pub/whois-data/APNIC/split/\n");

        put(QueryMessages.QueryMessageType.ACCESS_DENIED_PERMANENTLY, ""
                + "%%ERROR:201: access denied for %s\n"
                + "%%\n"
                + "%% Sorry, access from your host has been permanently denied\n"
                + "%% because of a repeated abusive behaviour.\n"
                + "%% Please contact <helpdesk@apnic.net> for unblocking.\n");

        put(QueryMessages.QueryMessageType.ACCESS_DENIED_TEMPORARILY, ""
                + "%%ERROR:201: access control limit reached for %s\n"
                + "%%\n"
                + "%% Queries from your IP address have passed the limit of returned contact information objects.\n"
                + "%% This connection will be terminated now.\n"
                + "%% Continued attempts to return excessive amounts of contact\n"
                + "%% information will result in permanent denial of service.\n"
                + "%% Please do not try to use CONTACT information in\n"
                + "%% My Database for non-operational purposes.\n"
                + "%% Refer to http://www.apnic.net/db/copyright.html for more information.\n");

        put(QueryMessages.QueryMessageType.TIMEOUT, ""
                + "%ERROR:305: connection has been closed\n"
                + "%\n"
                + "% The connection to the APNIC Whois server\n"
                + "% has been closed after a period of inactivity.\n");
    }

    private QueryMessagesMap() {
    }

    public static Map<QueryMessages.QueryMessageType, String> getQueryMessagesMap() {
        return queryMessages;
    }

    private static void put(QueryMessages.QueryMessageType key, String value) {
        // Test for duplicates
        if (queryMessages.put(key, value) != null) {
            throw new BeanInitializationException("Query Messages duplicate mapping exception: " + key);
        }
    }
}
