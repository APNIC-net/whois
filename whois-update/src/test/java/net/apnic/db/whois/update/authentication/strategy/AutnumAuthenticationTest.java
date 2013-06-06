package net.apnic.db.whois.update.authentication.strategy;

import com.google.common.collect.Lists;
import net.ripe.db.whois.common.dao.RpslObjectDao;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.RpslObject;
import net.ripe.db.whois.update.authentication.credential.AuthenticationModule;
import net.ripe.db.whois.update.authentication.strategy.AuthenticationFailedException;
import net.ripe.db.whois.update.domain.Action;
import net.ripe.db.whois.update.domain.PreparedUpdate;
import net.ripe.db.whois.update.domain.UpdateContext;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.anyCollection;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class AutnumAuthenticationTest {
    private static final Logger LOGGER = LoggerFactory.getLogger(AutnumAuthenticationTest.class);

    @Mock private RpslObjectDao objectDao;
    @Mock private PreparedUpdate update;
    @Mock private UpdateContext updateContext;
    @Mock private AuthenticationModule authenticationModule;

    @Rule
    public ExpectedException exception = ExpectedException.none();

    @InjectMocks
    AutnumAuthentication subject;

    @Test
    public void supports_autnum_create() {
        when(update.getAction()).thenReturn(Action.CREATE);
        when(update.getType()).thenReturn(ObjectType.AUT_NUM);

        final boolean supported = subject.supports(update);

        assertThat(supported, is(true));
    }

    @Test
    public void supports_other_than_autnum_create() {
        for (final ObjectType objectType : ObjectType.values()) {
            if (ObjectType.AUT_NUM.equals(objectType)) {
                continue;
            }

            when(update.getAction()).thenReturn(Action.CREATE);
            when(update.getType()).thenReturn(ObjectType.AS_BLOCK);
            final boolean supported = subject.supports(update);
            assertThat(supported, is(false));

            reset(update);
        }
    }

    @Test
    public void supports_autnum_modify() {
        when(update.getAction()).thenReturn(Action.MODIFY);
        when(update.getType()).thenReturn(ObjectType.AUT_NUM);

        final boolean supported = subject.supports(update);

        assertThat(supported, is(false));
    }

    @Test
    public void supports_autnum_delete() {
        when(update.getAction()).thenReturn(Action.DELETE);
        when(update.getType()).thenReturn(ObjectType.AUT_NUM);

        final boolean supported = subject.supports(update);

        assertThat(supported, is(false));
    }

    // No Parents - fail
    // 1 parent - success + MNT_BY & MNT_LOWER
    // 2 parents - success + MNT_BY & MNT_LOWER
    // 1 parent - fail - no maintainers that authenticate
    // 2 parent - fail - no maintainers that authenticate


    @Test
    public void no_parents_fails() {
        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("aut-num: AS3333"));

        List<RpslObject> returnRplsList = Lists.newArrayList();
        when(objectDao.findAsBlockIntersections(3333, 3333)).thenReturn(returnRplsList);

        returnRplsList.add(RpslObject.parse("as-block: AS1109 - AS2000\nmnt-lower: LOW-MNT"));
        returnRplsList.add(RpslObject.parse("as-block: AS1209 - AS1353\nmnt-lower: LOW-MNT"));

        exception.expect(AuthenticationFailedException.class);
        final List<RpslObject> authenticatedBy = subject.authenticate(update, updateContext);

    }

    @Test
    public void authenticated_by_mntby_succeeds() {
        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("aut-num: AS3333"));

        List<RpslObject> returnRplsList = Lists.newArrayList();

        returnRplsList.add(RpslObject.parse("as-block: AS3109 - AS5000\nmnt-by: BY-MNT"));
        returnRplsList.add(RpslObject.parse("as-block: AS3209 - AS3353\nmnt-by: BY-MNT"));

        when(objectDao.findAsBlockIntersections(3333, 3333)).thenReturn(returnRplsList);

        final ArrayList<RpslObject> parentMaintainers = Lists.newArrayList(RpslObject.parse("mntner: BY-MNT"));
        when(objectDao.getByKeys(eq(ObjectType.MNTNER), anyCollection())).thenReturn(parentMaintainers);
        when(authenticationModule.authenticate(update, updateContext, parentMaintainers)).thenReturn(parentMaintainers);

        final List<RpslObject> authenticatedBy = subject.authenticate(update, updateContext);

        assertThat(authenticatedBy.equals(parentMaintainers), is(true));
        verifyZeroInteractions(updateContext);
    }


    @Test
    public void authenticated_by_mntlower_succeeds() {
        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("aut-num: AS3333"));

        List<RpslObject> returnRplsList = Lists.newArrayList();

        returnRplsList.add(RpslObject.parse("as-block: AS3109 - AS5000\nmnt-lower: LOW-MNT"));
        returnRplsList.add(RpslObject.parse("as-block: AS3209 - AS3353\nmnt-lower: LOW-MNT"));

        when(objectDao.findAsBlockIntersections(3333, 3333)).thenReturn(returnRplsList);

        final ArrayList<RpslObject> parentMaintainers = Lists.newArrayList(RpslObject.parse("mntner: LOW-MNT"));
        when(objectDao.getByKeys(eq(ObjectType.MNTNER), anyCollection())).thenReturn(parentMaintainers);
        when(authenticationModule.authenticate(update, updateContext, parentMaintainers)).thenReturn(parentMaintainers);

        final List<RpslObject> authenticatedBy = subject.authenticate(update, updateContext);

        assertThat(authenticatedBy.equals(parentMaintainers), is(true));
        verifyZeroInteractions(updateContext);
    }

    @Test
    public void authenticated_by_mntby_x_succeeds() {
        List<RpslObject> emptyRplsList = Lists.newArrayList();
        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("aut-num: AS3111"));

        List<RpslObject> returnRplsList = Lists.newArrayList();

        returnRplsList.add(RpslObject.parse("as-block: AS3109 - AS5000\nmnt-by: BY-MNT"));
        returnRplsList.add(RpslObject.parse("as-block: AS3209 - AS3353\nmnt-lower: LOW-MNT"));

        when(objectDao.findAsBlockIntersections(3111, 3111)).thenReturn(returnRplsList);

        final ArrayList<RpslObject> parentMaintainers = Lists.newArrayList(RpslObject.parse("mntner: XLOW-MNT"));
        when(objectDao.getByKeys(eq(ObjectType.MNTNER), anyCollection())).thenReturn(parentMaintainers);
        when(authenticationModule.authenticate(update, updateContext, parentMaintainers)).thenReturn(emptyRplsList);

        try {
            final List<RpslObject> authenticatedBy = subject.authenticate(update, updateContext);
            throw new UnsupportedOperationException("should not get here");
        } catch (AuthenticationFailedException afe) {
            assertEquals(afe.getAuthenticationMessages().size(), 2);
            LOGGER.info("Error: " + afe.getAuthenticationMessages().get(0).toString());
            LOGGER.info("Error: " + afe.getAuthenticationMessages().get(1).toString());
        }

       // assertThat(authenticatedBy.equals(parentMaintainers), is(true));
        verifyZeroInteractions(updateContext);
    }

//    @Test(expected = AuthenticationFailedException.class)
//    public void authenticated_by_mntlower_fails() {
//        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("aut-num: AS3333"));
//        when(objectDao.findAsBlock(3333, 3333)).thenReturn(RpslObject.parse("as-block: AS3209 - AS3353\nmnt-by: TEST-MNT\nmnt-lower: LOW-MNT"));
//
//        final ArrayList<RpslObject> parentMaintainers = Lists.newArrayList(RpslObject.parse("mntner: LOW-MNT"));
//        when(objectDao.getByKeys(eq(ObjectType.MNTNER), anyCollection())).thenReturn(parentMaintainers);
//        when(authenticationModule.authenticate(update, updateContext, parentMaintainers)).thenReturn(Lists.<RpslObject>newArrayList());
//
//        subject.authenticate(update, updateContext);
//    }
//
//    @Test(expected = AuthenticationFailedException.class)
//    public void cant_find_asblock() {
//        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("aut-num: AS3333"));
//        when(objectDao.findAsBlock(3333, 3333)).thenReturn(null);
//
//        subject.authenticate(update, updateContext);
//    }
//
//    @Test
//    public void authenticated_by_mntby_succeeds() {
//        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("aut-num: AS3333"));
//        when(objectDao.findAsBlock(3333, 3333)).thenReturn(RpslObject.parse("as-block: AS3209 - AS3353\nmnt-by: TEST-MNT"));
//
//        final ArrayList<RpslObject> parentMaintainers = Lists.newArrayList(RpslObject.parse("mntner: TEST-MNT"));
//        when(objectDao.getByKeys(eq(ObjectType.MNTNER), anyCollection())).thenReturn(parentMaintainers);
//        when(authenticationModule.authenticate(update, updateContext, parentMaintainers)).thenReturn(parentMaintainers);
//
//        final List<RpslObject> authenticatedBy = subject.authenticate(update, updateContext);
//
//        assertThat(authenticatedBy.equals(parentMaintainers), is(true));
//        verifyZeroInteractions(updateContext);
//    }
//
//    @Test(expected = AuthenticationFailedException.class)
//    public void authenticated_by_mntby_fails() {
//        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("aut-num: AS3333"));
//        when(objectDao.findAsBlock(3333, 3333)).thenReturn(RpslObject.parse("as-block: AS3209 - AS3353\nmnt-by: TEST-MNT"));
//
//        final ArrayList<RpslObject> parentMaintainers = Lists.newArrayList(RpslObject.parse("mntner: TEST-MNT"));
//        when(objectDao.getByKeys(eq(ObjectType.MNTNER), anyCollection())).thenReturn(parentMaintainers);
//        when(authenticationModule.authenticate(update, updateContext, parentMaintainers)).thenReturn(Lists.<RpslObject>newArrayList());
//
//        subject.authenticate(update, updateContext);
//    }
//
//    @Test
//    public void max_value() {
//        final long maxValue = (1L << 32) - 1;
//        final RpslObject autNum = RpslObject.parse("aut-num: AS" + maxValue);
//        final RpslObject asBlock = RpslObject.parse("as-block: AS" + (maxValue - 1) + " - AS" + maxValue + "\nmnt-by: TEST-MNT");
//
//        when(update.getUpdatedObject()).thenReturn(autNum);
//        when(objectDao.findAsBlock(maxValue, maxValue)).thenReturn(asBlock);
//
//        final ArrayList<RpslObject> parentMaintainers = Lists.newArrayList(RpslObject.parse("mntner: TEST-MNT"));
//        when(objectDao.getByKeys(eq(ObjectType.MNTNER), anyCollection())).thenReturn(parentMaintainers);
//        when(authenticationModule.authenticate(update, updateContext, parentMaintainers)).thenReturn(parentMaintainers);
//
//        subject.authenticate(update, updateContext);
//
//        verifyZeroInteractions(updateContext);
//    }
}
