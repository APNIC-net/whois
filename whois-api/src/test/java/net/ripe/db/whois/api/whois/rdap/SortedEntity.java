package net.ripe.db.whois.api.whois.rdap;

import com.google.common.collect.Lists;
import net.ripe.db.whois.api.whois.rdap.domain.Entity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.List;

public class SortedEntity extends Entity implements Comparable<Entity> {
    private static final Logger LOGGER = LoggerFactory.getLogger(SortedEntity.class);

    public static List<SortedEntity> createSortedEntities(List<Entity> entities) {
        List<SortedEntity> ret = Lists.newArrayList();
        try {
            // Deep clone entity to sortedEntity
            for (Entity entity : entities) {
                SortedEntity sortedEntity = (SortedEntity) RdapHelperUtils.cloneObject(entity, SortedEntity.class);
                ret.add(sortedEntity);
            }
        } catch (Exception ex) {
            LOGGER.error("Could not clone entity", ex);
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
    public int compareTo(Entity o) {
        int result = nullSafeStringComparator(getHandle(), o.getHandle());
        if (result != 0) {
            return result;
        }
        return nullSafeStringComparator(getHandle(), o.getHandle());
    }
}
