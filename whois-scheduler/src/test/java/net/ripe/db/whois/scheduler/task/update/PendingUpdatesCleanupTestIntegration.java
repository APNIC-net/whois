package net.ripe.db.whois.scheduler.task.update;

import net.ripe.db.whois.common.IntegrationTest;
import net.ripe.db.whois.common.TestDateTimeProvider;
import net.ripe.db.whois.common.rpsl.RpslObjectBase;
import net.ripe.db.whois.scheduler.AbstractSchedulerIntegrationTest;
import org.joda.time.LocalDate;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.springframework.beans.factory.annotation.Autowired;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

@Category(IntegrationTest.class)
public class PendingUpdatesCleanupTestIntegration extends AbstractSchedulerIntegrationTest {

    @Autowired PendingUpdatesCleanup pendingUpdatesCleanup;
    @Autowired TestDateTimeProvider dateTimeProvider;

    @Test
    public void cleanup() {
        final RpslObjectBase route = RpslObjectBase.parse(
                "route: 10.0.0.0/8\n" +
                "descr: description\n" +
                "origin: \n" +
                "notify: noreply@ripe.net\n" +
                "mnt-by: OWNER-MNT\n" +
                "changed: noreplY@ripe.net\n" +
                "source: TEST");

        databaseHelper.clearPendingUpdates();
        databaseHelper.insertPendingUpdate(LocalDate.now().minusDays(8), "OWNER-MNT", route);
        assertThat(databaseHelper.listPendingUpdates(), hasSize(1));

        pendingUpdatesCleanup.run();

        assertThat(databaseHelper.listPendingUpdates(), hasSize(0));
    }
}
