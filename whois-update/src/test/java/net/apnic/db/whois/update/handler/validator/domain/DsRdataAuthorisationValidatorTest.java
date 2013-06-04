package net.apnic.db.whois.update.handler.validator.domain;

import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.RpslObject;
import net.ripe.db.whois.update.authentication.Subject;
import net.ripe.db.whois.update.domain.Action;
import net.ripe.db.whois.update.domain.Origin;
import net.ripe.db.whois.update.domain.OverrideOptions;
import net.ripe.db.whois.update.domain.PreparedUpdate;
import net.ripe.db.whois.update.domain.Update;
import net.ripe.db.whois.update.domain.UpdateContext;
import net.ripe.db.whois.update.domain.UpdateMessages;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class DsRdataAuthorisationValidatorTest {
    @Mock
    Update updateContainer;
    @Mock
    PreparedUpdate update;
    @Mock
    UpdateContext updateContext;
    @Mock
    Subject authSubject;
    @Mock
    Origin origin;
    @InjectMocks
    DsRdataAuthorisationValidator subject;

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

    @Test
    public void validate_override() {
        when(update.isOverride()).thenReturn(true);
        subject.validate(update, updateContext);
        verifyZeroInteractions(updateContext);
    }

    @Test
    public void not_supports_other_origin() {
        when(update.getOrigin()).thenReturn(new MockOrigin(Origin.Type.SYNC_UPDATE));
        subject.validate(update, updateContext);
        verifyZeroInteractions(updateContext);
    }

    @Test
    public void validate_no_ds_data_in_update_and_original() {
        when(update.getOrigin()).thenReturn(new MockOrigin(Origin.Type.EMAIL_UPDATE));

        when(update.getAction()).thenReturn(Action.MODIFY);
        when(update.getReferenceObject()).thenReturn(RpslObject.parse("domain: 29.12.202.in-addr.arpa"));
        when(update.getUpdatedObject()).thenReturn(RpslObject.parse("domain: 29.12.202.in-addr.arpa"));

        subject.validate(update, updateContext);
        verify(updateContext, never()).addMessage(update, UpdateMessages.attributeDsRdataCannotBeModified());
    }

    @Test
    public void validate_ds_data_in_update_and_not_in_original() {
        final RpslObject rpslObjectOriginal = RpslObject.parse("domain: 29.12.202.in-addr.arpa");
        final RpslObject rpslObjectUpdated = RpslObject.parse("domain: 29.12.202.in-addr.arpa\nds-rdata: 52151 1 1 13ee60f7499a70e5aadaf05828e7fc59e8e70bc1");

        when(origin.getType()).thenReturn(Origin.Type.EMAIL_UPDATE);

        PreparedUpdate updateInstance = new PreparedUpdate(updateContainer, rpslObjectOriginal, rpslObjectUpdated, Action.MODIFY, origin, OverrideOptions.NONE);
        subject.validate(updateInstance, updateContext);
        verify(updateContext).addMessage(updateInstance, UpdateMessages.attributeDsRdataCannotBeModified());
    }

    @Test
    public void validate_no_ds_data_in_update_but_in_original() {
        final RpslObject rpslObjectOriginal = RpslObject.parse("domain: 29.12.202.in-addr.arpa\nds-rdata: 52151 1 1 13ee60f7499a70e5aadaf05828e7fc59e8e70bc1");
        final RpslObject rpslObjectUpdated = RpslObject.parse("domain: 29.12.202.in-addr.arpa");

        when(origin.getType()).thenReturn(Origin.Type.EMAIL_UPDATE);

        PreparedUpdate updateInstance = new PreparedUpdate(updateContainer, rpslObjectOriginal, rpslObjectUpdated, Action.MODIFY, origin, OverrideOptions.NONE);
        subject.validate(updateInstance, updateContext);
        verify(updateContext).addMessage(updateInstance, UpdateMessages.attributeDsRdataCannotBeModified());
    }

    @Test
    public void validate_ds_data_in_update_and_in_original() {
        final RpslObject rpslObjectOriginal = RpslObject.parse("domain: 29.12.202.in-addr.arpa\nds-rdata: 52151 1 1 13ee60f7499a70e5aadaf05828e7fc59e8e70bc1");
        final RpslObject rpslObjectUpdated = RpslObject.parse("domain: 29.12.202.in-addr.arpa\nds-rdata: 52151 1 1 13ee60f7499a70e5aadaf05828e7fc59e8e70bc1");

        when(origin.getType()).thenReturn(Origin.Type.EMAIL_UPDATE);

        PreparedUpdate updateInstance = new PreparedUpdate(updateContainer, rpslObjectOriginal, rpslObjectUpdated, Action.MODIFY, origin, OverrideOptions.NONE);
        subject.validate(updateInstance, updateContext);
        verify(updateContext, never()).addMessage(updateInstance, UpdateMessages.attributeDsRdataCannotBeModified());
    }


    @Test
    public void validate_ds_data_in_update_and_in_original_but_delete() {
        final RpslObject rpslObjectOriginal = RpslObject.parse("domain: 29.12.202.in-addr.arpa\nds-rdata: 52151 1 1 13ee60f7499a70e5aadaf05828e7fc59e8e70bc1");
        final RpslObject rpslObjectUpdated = RpslObject.parse("domain: 29.12.202.in-addr.arpa\nds-rdata: 52151 1 1 13ee60f7499a70e5aadaf05828e7fc59e8e70bc1");

        when(origin.getType()).thenReturn(Origin.Type.EMAIL_UPDATE);

        PreparedUpdate updateInstance = new PreparedUpdate(updateContainer, rpslObjectOriginal, rpslObjectUpdated, Action.DELETE, origin, OverrideOptions.NONE);

        subject.validate(updateInstance, updateContext);
        verify(updateContext).addMessage(updateInstance, UpdateMessages.attributeDsRdataCannotBeModified());
    }


    @Test
    public void validate_ds_data_in_update_and_in_original_but_out_of_order() {
        final RpslObject rpslObjectOriginal = RpslObject.parse("domain: 29.12.202.in-addr.arpa\nds-rdata: 52151 1 1 13ee60f7499a70e5aadaf05828e7fc59e8e70bc1\nds-rdata: 52151 1 1 23ee60f7499a70e5aadaf05828e7fc59e8e70bc2");
        final RpslObject rpslObjectUpdated = RpslObject.parse("domain: 29.12.202.in-addr.arpa\nds-rdata: 52151 1 1 23ee60f7499a70e5aadaf05828e7fc59e8e70bc2\nds-rdata: 52151 1 1 13ee60f7499a70e5aadaf05828e7fc59e8e70bc1");

        when(origin.getType()).thenReturn(Origin.Type.EMAIL_UPDATE);

        PreparedUpdate updateInstance = new PreparedUpdate(updateContainer, rpslObjectOriginal, rpslObjectUpdated, Action.MODIFY, origin, OverrideOptions.NONE);
        subject.validate(updateInstance, updateContext);
        verify(updateContext, never()).addMessage(updateInstance, UpdateMessages.attributeDsRdataCannotBeModified());
    }

    static class MockOrigin implements Origin {
        Type type;

        MockOrigin(Type type) {
            this.type = type;
        }

        @Override
        public boolean isDefaultOverride() {
            return false;
        }

        @Override
        public boolean allowAdminOperations() {
            return false;
        }

        @Override
        public String getId() {
            return null;
        }

        @Override
        public String getFrom() {
            return null;
        }

        @Override
        public String getResponseHeader() {
            return null;
        }

        @Override
        public String getNotificationHeader() {
            return null;
        }

        @Override
        public String getName() {
            return type.getName();
        }

        @Override
        public Type getType() {
            return type;
        }
    }
}

