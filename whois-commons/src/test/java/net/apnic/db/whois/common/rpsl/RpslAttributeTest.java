package net.apnic.db.whois.common.rpsl;

import net.ripe.db.whois.common.rpsl.ObjectMessages;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.RpslAttribute;
import net.ripe.db.whois.common.rpsl.ValidationMessages;
import org.junit.Test;

import static org.hamcrest.Matchers.contains;
import static org.junit.Assert.assertThat;

public class RpslAttributeTest {

    @Test
    public void validateSyntax_syntax_error_and_invalid_email() {
        final ObjectMessages objectMessages = new ObjectMessages();
        final RpslAttribute rpslAttribute = new RpslAttribute("inetnum", "auto-dbm@apnic.net");
        rpslAttribute.validateSyntax(ObjectType.INETNUM, objectMessages);

        assertThat(objectMessages.getMessages(rpslAttribute).getAllMessages(), contains(ValidationMessages.syntaxError("auto-dbm@apnic.net")));
    }

    @Test
    public void validateSyntax_syntax_valid_and_auto_dbm() {
        final ObjectMessages objectMessages = new ObjectMessages();
        final RpslAttribute rpslAttribute = new RpslAttribute("remarks", "auto-dbm@apnic.net");
        rpslAttribute.validateSyntax(ObjectType.DOMAIN, objectMessages);

        assertThat(objectMessages.getMessages(rpslAttribute).getAllMessages(), contains(ValidationMessages.emailAddressNotAllowed("auto-dbm@apnic.net")));
    }

    @Test
    public void validateSyntax_syntax_valid_and_test_dbm() {
        final ObjectMessages objectMessages = new ObjectMessages();
        final RpslAttribute rpslAttribute = new RpslAttribute("remarks", "TEST-dbm@apnic.net");
        rpslAttribute.validateSyntax(ObjectType.DOMAIN, objectMessages);

        assertThat(objectMessages.getMessages(rpslAttribute).getAllMessages(), contains(ValidationMessages.emailAddressNotAllowed("TEST-dbm@apnic.net")));
    }

    @Test
    public void validateSyntax_syntax_valid_and_invalid_email_contains() {
        final ObjectMessages objectMessages = new ObjectMessages();
        final RpslAttribute rpslAttribute = new RpslAttribute("remarks", "Some remark about auto-dbm@APNIC.net should be detected");
        rpslAttribute.validateSyntax(ObjectType.DOMAIN, objectMessages);

        assertThat(objectMessages.getMessages(rpslAttribute).getAllMessages(), contains(ValidationMessages.emailAddressNotAllowed("auto-dbm@APNIC.net")));
    }

}
