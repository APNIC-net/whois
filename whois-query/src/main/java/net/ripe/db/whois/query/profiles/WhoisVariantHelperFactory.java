package net.ripe.db.whois.query.profiles;

import net.ripe.db.whois.common.profiles.WhoisVariant;
import net.ripe.db.whois.query.domain.QueryMessages;
import net.ripe.db.whois.query.domain.QueryMessagesMap;

import java.util.Map;

public class WhoisVariantHelperFactory {


    public static Map<QueryMessages.QueryMessageType, String> getQueryMessagesMap() {
        Map<QueryMessages.QueryMessageType, String> ret = QueryMessagesMap.getQueryMessagesMap();

        if (WhoisVariant.isAPNIC()) {
            return net.apnic.db.whois.query.domain.QueryMessagesMap.getQueryMessagesMap();
        }
        return ret;
    }

}
