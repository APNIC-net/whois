package net.ripe.db.whois.api.whois.rdap;

import com.google.common.collect.Lists;
import net.ripe.db.whois.api.whois.rdap.domain.Link;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.List;

public class SortedLink extends Link implements Comparable<Link> {
    private static final Logger LOGGER = LoggerFactory.getLogger(SortedLink.class);
    public static List<SortedLink> createSortedLinks(List<Link> links) {
        List<SortedLink> ret = Lists.newArrayList();
        try {
            // Deep clone link to sortedLink
            for (Link link : links) {
                SortedLink sortedLink = (SortedLink) RdapHelperUtils.cloneObject(link, SortedLink.class);
                ret.add(sortedLink);
            }
        } catch (Exception ex) {
            LOGGER.error("Could not clone link", ex);
        }
        Collections.sort(ret);
        return ret;
    }

    public static int nullSafeStringComparator(final String one, final String two) {
        if (one == null ^ two == null) {
            return (one == null) ? -1 : 1;
        }

        if (one == null && two == null) {
            return 0;
        }

        return one.compareToIgnoreCase(two);
    }

    @Override
    public int compareTo(Link o) {
        int result = nullSafeStringComparator(getValue(), o.getValue());
        if (result != 0) {
            return result;
        }
        return nullSafeStringComparator(getValue(), o.getValue());
    }
}

