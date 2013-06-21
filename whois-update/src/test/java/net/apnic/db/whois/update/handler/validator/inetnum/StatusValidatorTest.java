package net.apnic.db.whois.update.handler.validator.inetnum;

import com.google.common.collect.Lists;
import net.ripe.db.whois.common.dao.RpslObjectDao;
import net.ripe.db.whois.common.domain.CIString;
import net.ripe.db.whois.common.domain.Ipv4Resource;
import net.ripe.db.whois.common.domain.Maintainers;
import net.ripe.db.whois.common.iptree.Ipv4Entry;
import net.ripe.db.whois.common.iptree.Ipv4Tree;
import net.ripe.db.whois.common.iptree.Ipv6Tree;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.RpslObject;
import net.ripe.db.whois.update.authentication.Subject;
import net.ripe.db.whois.update.domain.Action;
import net.ripe.db.whois.update.domain.PreparedUpdate;
import net.ripe.db.whois.update.domain.UpdateContext;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class StatusValidatorTest {

    @Mock PreparedUpdate update;
    @Mock UpdateContext updateContext;
    @Mock RpslObjectDao objectDao;
    @Mock Ipv4Tree ipv4Tree;
    @Mock Ipv6Tree ipv6Tree;
    @Mock Ipv4Entry ipEntry;
    @Mock Subject authenticationSubject;
    @Mock Maintainers maintainers;
    @InjectMocks
    StatusValidator subject;

    @Before
    public void setup() {
        when(update.getAction()).thenReturn(Action.CREATE);
        when(update.getType()).thenReturn(ObjectType.INETNUM);
    }

    @Test
    public void portable_inetnum_requires_maintainer_ip4v_success() {
        when(update.getType()).thenReturn(ObjectType.INETNUM);
        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("inetnum: 192.0/24\nstatus: ASSIGNED PORTABLE\nMNT-BY: APNIC-HM-MNT"));
        when(maintainers.getAllocMaintainers()).thenReturn(CIString.ciSet("APNIC-HM-MNT"));
        subject.validate(update, updateContext);
        verifyZeroInteractions(updateContext);
    }

    @Test
    public void portable_inetnum_requires_maintainer_ip4v_fail() {
        when(update.getType()).thenReturn(ObjectType.INETNUM);
        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("inetnum: 192.0/24\nstatus: ASSIGNED PORTABLE\nMNT-BY: APNIC-HM-MNT"));
        subject.validate(update, updateContext);
        verify(updateContext).addMessage(update, net.apnic.db.whois.update.domain.UpdateMessages.portableStatusRequiresAllocMaintainer());
    }

    @Test
    public void check_parent_status_ip4v_incorrect_maintainer_fail() {
        when(update.getType()).thenReturn(ObjectType.INETNUM);
        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("inetnum: 192.0/24\nstatus: ASSIGNED PORTABLE\nMNT-BY: BY-MNT"));
        when(maintainers.getAllocMaintainers()).thenReturn(CIString.ciSet("APNIC-HM-MNT"));
        subject.validate(update, updateContext);
        verify(updateContext).addMessage(update, net.apnic.db.whois.update.domain.UpdateMessages.portableStatusRequiresAllocMaintainer());
    }

    @Test
    public void check_parent_status_no_parent_ip4v_fail() {
        when(update.getType()).thenReturn(ObjectType.INETNUM);
        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("inetnum: 192.0/24\nstatus: ASSIGNED NON-PORTABLE\nMNT-BY: APNIC-HM-MNT"));

        subject.validate(update, updateContext);
        verify(updateContext).addMessage(update, net.apnic.db.whois.update.domain.UpdateMessages.hasNoParents(anyString(), any(CIString.class)));
    }

    @Test
    public void check_parent_status_ip4v_fail() {
        when(update.getType()).thenReturn(ObjectType.INETNUM);
        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("inetnum: 192.0/24\nstatus: ASSIGNED NON-PORTABLE\nMNT-BY: APNIC-HM-MNT"));

        final Ipv4Resource ipv4Resource = Ipv4Resource.parse("192.0/24");
        final Ipv4Entry ipv4Entryparent = new Ipv4Entry(ipv4Resource, 1);

        when(objectDao.getById(anyInt())).thenReturn(RpslObject.parse("inetnum: 192.0/22\nstatus: ASSIGNED NON-PORTABLE\nMNT-BY: APNIC-HM-MNT"));
        when(ipv4Tree.findAllLessSpecific(any(Ipv4Resource.class))).thenReturn(Lists.newArrayList(ipv4Entryparent));

        subject.validate(update, updateContext);
        verify(updateContext).addMessage(update, net.apnic.db.whois.update.domain.UpdateMessages.invalidParentStatus(CIString.ciString("192.0/22"), StatusValidator.allowedParentInetStatusMessage));
    }

    @Test
    public void check_parent_status_ip4v_ac_non_portable_success() {
        when(update.getType()).thenReturn(ObjectType.INETNUM);
        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("inetnum: 192.0/24\nstatus: ASSIGNED NON-PORTABLE\nMNT-BY: APNIC-HM-MNT"));

        final Ipv4Resource ipv4Resource = Ipv4Resource.parse("192.0/24");
        final Ipv4Entry ipv4Entryparent = new Ipv4Entry(ipv4Resource, 1);

        when(objectDao.getById(anyInt())).thenReturn(RpslObject.parse("inetnum: 192.0/22\nstatus: ALLOCATED NON-PORTABLE\nMNT-BY: APNIC-HM-MNT"));
        when(ipv4Tree.findAllLessSpecific(any(Ipv4Resource.class))).thenReturn(Lists.newArrayList(ipv4Entryparent));

        subject.validate(update, updateContext);
        verifyZeroInteractions(updateContext);
    }

    @Test
    public void check_parent_status_ip4v_alloc_portable_success() {
        when(update.getType()).thenReturn(ObjectType.INETNUM);
        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("inetnum: 192.0/24\nstatus: ASSIGNED NON-PORTABLE\nMNT-BY: APNIC-HM-MNT"));

        final Ipv4Resource ipv4Resource = Ipv4Resource.parse("192.0/24");
        final Ipv4Entry ipv4Entryparent = new Ipv4Entry(ipv4Resource, 1);

        when(objectDao.getById(anyInt())).thenReturn(RpslObject.parse("inetnum: 192.0/22\nstatus: ALLOCATED PORTABLE\nMNT-BY: APNIC-HM-MNT"));
        when(ipv4Tree.findAllLessSpecific(any(Ipv4Resource.class))).thenReturn(Lists.newArrayList(ipv4Entryparent));

        subject.validate(update, updateContext);
        verifyZeroInteractions(updateContext);
    }


}
