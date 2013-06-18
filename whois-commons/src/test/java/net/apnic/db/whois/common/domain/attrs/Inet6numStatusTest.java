package net.apnic.db.whois.common.domain.attrs;


import net.ripe.db.whois.common.domain.CIString;
import org.junit.Ignore;
import org.junit.Test;

import static net.apnic.db.whois.common.domain.attrs.Inet6numStatus.*;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

@Ignore
public class Inet6numStatusTest {

    @Test
    public void getLiteralStatus() {
        assertThat(ALLOCATED_NON_PORTABLE.getLiteralStatus(), is(CIString.ciString("ALLOCATED NON-PORTABLE")));
        assertThat(ALLOCATED_PORTABLE.getLiteralStatus(), is(CIString.ciString("ALLOCATED PORTABLE")));
        assertThat(ASSIGNED_PORTABLE.getLiteralStatus(), is(CIString.ciString("ASSIGNED PORTABLE")));
        assertThat(ASSIGNED_NON_PORTABLE.getLiteralStatus(), is(CIString.ciString("ASSIGNED NON-PORTABLE")));
    }

    @Test
    public void getStatusFor() {
        assertThat(Inet6numStatus.getStatusFor(CIString.ciString("ALLOCATED NON-PORTABLE")), is(ALLOCATED_NON_PORTABLE));
        assertThat(Inet6numStatus.getStatusFor(CIString.ciString("ALLOCATED PORTABLE")), is(ALLOCATED_PORTABLE));
        assertThat(Inet6numStatus.getStatusFor(CIString.ciString("ASSIGNED PORTABLE")), is(ASSIGNED_PORTABLE));
        assertThat(Inet6numStatus.getStatusFor(CIString.ciString("ASSIGNED NON-PORTABLE")), is(ASSIGNED_NON_PORTABLE));

        try {
            Inet6numStatus.getStatusFor(CIString.ciString("WHATEVER"));
            fail();
        } catch (Exception expected) {}
    }
}
