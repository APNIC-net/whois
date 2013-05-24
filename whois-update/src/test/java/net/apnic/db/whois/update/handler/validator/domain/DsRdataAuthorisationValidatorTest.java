package net.apnic.db.whois.update.handler.validator.domain;

import net.ripe.db.whois.common.rpsl.ObjectType;
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

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class DsRdataAuthorisationValidatorTest {
    @Mock PreparedUpdate update;
    @Mock UpdateContext updateContext;
    @Mock Subject authSubject;
    @InjectMocks DsRdataAuthorisationValidator subject;

    @Before
    public void setUp() throws Exception {
        when(updateContext.getSubject(update)).thenReturn(authSubject);
    }

    @Test
    public void getActions() {
        assertThat(subject.getActions(), containsInAnyOrder(Action.CREATE, Action.MODIFY, Action.DELETE));
    }

    @Test
    public void getTypes() {
        assertThat(subject.getTypes(), containsInAnyOrder(ObjectType.DOMAIN));
    }
// @TODO
//    @Test
//    public void validate_non_enum() {
//        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("" +
//                "domain: 200.193.193.in-addr.arpa"));
//
//        subject.validate(update, updateContext);
//        verifyZeroInteractions(updateContext);
//    }
//
//    @Test
//    public void validate_override() {
//        when(update.isOverride()).thenReturn(true);
//        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("domain: 2.1.2.1.5.5.5.2.0.2.1.e164.arpa"));
//
//        when(authSubject.hasPrincipal(Principal.ENUM_MAINTAINER)).thenReturn(false);
//
//        subject.validate(update, updateContext);
//        verifyZeroInteractions(updateContext);
//    }
//
//    @Test
//    public void validate_enum_no_enum_maintainer() {
//        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("" +
//                "domain: 2.1.2.1.5.5.5.2.0.2.1.e164.arpa"));
//
//        when(authSubject.hasPrincipal(Principal.ENUM_MAINTAINER)).thenReturn(false);
//
//        subject.validate(update, updateContext);
//
//        verify(authSubject).hasPrincipal(Principal.ENUM_MAINTAINER);
//        verify(updateContext).addMessage(update, UpdateMessages.authorisationRequiredForEnumDomain());
//    }
//
//    @Test
//    public void validate_enum_with_enum_maintainer() {
//        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("" +
//                "domain: 2.1.2.1.5.5.5.2.0.2.1.e164.arpa"));
//
//        when(authSubject.hasPrincipal(Principal.ENUM_MAINTAINER)).thenReturn(true);
//
//        subject.validate(update, updateContext);
//
//        verify(authSubject).hasPrincipal(Principal.ENUM_MAINTAINER);
//        verify(updateContext, never()).addMessage(update, UpdateMessages.authorisationRequiredForEnumDomain());
//    }




//    @Test
//    public void supports_mailmessage_origin() {
//        when(emailOrigin.getName()).thenReturn(Origin.Type.EMAIL_UPDATE.getName());
//        when(mockPreparedUpdate.getType()).thenReturn(ObjectType.DOMAIN);
//        assertThat(subject.supports(mockPreparedUpdate, emailOrigin), is(true));
//    }
//
//    @Test
//    public void supports_mailmessage_different_objecttype() {
//        when(emailOrigin.getName()).thenReturn(Origin.Type.EMAIL_UPDATE.getName());
//        when(mockPreparedUpdate.getType()).thenReturn(ObjectType.PERSON);
//        assertThat(subject.supports(mockPreparedUpdate, emailOrigin), is(false));
//    }
//
//    @Test
//    public void supports_different_origin() {
//        when(someOtherOrigin.getName()).thenReturn(Origin.Type.REST_API.getName());
//        when(mockPreparedUpdate.getType()).thenReturn(ObjectType.DOMAIN);
//        assertThat(subject.supports(mockPreparedUpdate, someOtherOrigin), is(false));
//    }
//
//    @Test
//    public void authenticate_no_ds_data() {
//        final RpslObject rpslObjectOriginal = RpslObject.parse("" +
//                "domain: 0.0.0.0.8.f.7.0.1.0.0.2.ip6.arpa");
//
//        final RpslObject rpslObjectUpdated = RpslObject.parse("" +
//                "domain: 0.0.0.0.8.f.7.0.1.0.0.2.ip6.arpa\n");
//
//        PreparedUpdate updateInstance = new PreparedUpdate(update, rpslObjectOriginal, rpslObjectUpdated, Action.MODIFY);
//
//        final List<RpslObject> authenticated = subject.authenticate(updateInstance, updateContext);
//        assertThat(authenticated, hasSize(0));
//
//        verifyZeroInteractions(ipv4Tree, ipv6Tree, objectDao);
//    }
//
//    @Test
//    public void authenticate_same_ds_data() {
//        final RpslObject rpslObjectOriginal = RpslObject.parse("" +
//                "domain: 0.0.0.0.8.f.7.0.1.0.0.2.ip6.arpa\n" +
//                "ds-rdata:       52151  1  1  13ee60f7499a70e5aadaf05828e7fc59e8e70bc1");
//
//
//        final RpslObject rpslObjectUpdated = RpslObject.parse("" +
//                "domain: 0.0.0.0.8.f.7.0.1.0.0.2.ip6.arpa\n" +
//                "ds-rdata: 52151 1 1 13ee60f7499a70e5aadaf05828e7fc59e8e70bc1");
//
//        PreparedUpdate updateInstance = new PreparedUpdate(update, rpslObjectOriginal, rpslObjectUpdated, Action.MODIFY);
//
//        final List<RpslObject> authenticated = subject.authenticate(updateInstance, updateContext);
//        assertThat(authenticated, hasSize(0));
//
//        verifyZeroInteractions(ipv4Tree, ipv6Tree, objectDao);
//    }
//
//    @Test
//    public void authenticate_different_order_ds_data() {
//        final RpslObject rpslObjectOriginal = RpslObject.parse("" +
//                "domain: 0.0.0.0.8.f.7.0.1.0.0.2.ip6.arpa\n" +
//                "ds-rdata:       52151  1  1  13ee60f7499a70e5aadaf05828e7fc59e8e70bc2\n" +
//                "ds-rdata:       52151  1  1  13ee60f7499a70e5aadaf05828e7fc59e8e70bc1");
//
//        final RpslObject rpslObjectUpdated = RpslObject.parse("" +
//                "domain: 0.0.0.0.8.f.7.0.1.0.0.2.ip6.arpa\n" +
//                "ds-rdata: 52151 1 1 13ee60f7499a70e5aadaf05828e7fc59e8e70bc1\n" +
//                "ds-rdata: 52151 1 1 13ee60f7499a70e5aadaf05828e7fc59e8e70bc2");
//
//        PreparedUpdate updateInstance = new PreparedUpdate(update, rpslObjectOriginal, rpslObjectUpdated, Action.MODIFY);
//
//        final List<RpslObject> authenticated = subject.authenticate(updateInstance, updateContext);
//        assertThat(authenticated, hasSize(0));
//
//        verifyZeroInteractions(ipv4Tree, ipv6Tree, objectDao);
//    }
//
//    @Test(expected = IllegalArgumentException.class)
//    public void authenticate_ds_data_exists_original() {
//        final RpslObject rpslObjectOriginal = RpslObject.parse("" +
//                "domain: 0.0.0.0.8.f.7.0.1.0.0.2.ip6.arpa\n" +
//                "ds-rdata:       52151  1  1  13ee60f7499a70e5aadaf05828e7fc59e8e70bc1");
//
//        final RpslObject rpslObjectUpdated = RpslObject.parse("" +
//                "domain: 0.0.0.0.8.f.7.0.1.0.0.2.ip6.arpa\n");
//
//        PreparedUpdate updateInstance = new PreparedUpdate(update, rpslObjectOriginal, rpslObjectUpdated, Action.MODIFY);
//
//        final List<RpslObject> authenticated = subject.authenticate(updateInstance, updateContext);
//        assertThat(authenticated, hasSize(0));
//
//        verifyZeroInteractions(ipv4Tree, ipv6Tree, objectDao);
//    }
//
//    @Test(expected = IllegalArgumentException.class)
//    public void authenticate_ds_data_exists_uppdate() {
//        final RpslObject rpslObjectOriginal = RpslObject.parse("" +
//                "domain: 0.0.0.0.8.f.7.0.1.0.0.2.ip6.arpa\n");
//
//        final RpslObject rpslObjectUpdated = RpslObject.parse("" +
//                "domain: 0.0.0.0.8.f.7.0.1.0.0.2.ip6.arpa\n" +
//                "ds-rdata:       52151  1  1  13ee60f7499a70e5aadaf05828e7fc59e8e70bc1");
//
//        PreparedUpdate updateInstance = new PreparedUpdate(update, rpslObjectOriginal, rpslObjectUpdated, Action.MODIFY);
//
//        final List<RpslObject> authenticated = subject.authenticate(updateInstance, updateContext);
//        assertThat(authenticated, hasSize(0));
//
//        verifyZeroInteractions(ipv4Tree, ipv6Tree, objectDao);
//    }
}

