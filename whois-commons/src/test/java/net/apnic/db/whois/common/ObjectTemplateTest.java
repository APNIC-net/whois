package net.apnic.db.whois.common;

import net.ripe.db.whois.common.rpsl.ObjectTemplate;
import net.ripe.db.whois.common.rpsl.ObjectType;
import org.junit.Test;

import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertThat;

public class ObjectTemplateTest {
    @Test
    public void verboseStringTemplateOrganisation() {
        final String template = ObjectTemplate.getTemplate(ObjectType.ORGANISATION).toVerboseString();

        assertThat(template, containsString("" +
                "org-type\n" +
                "\n" +
                "   Specifies the type of the organisation.\n" +
                "\n" +
                "     org-type can have one of these values:\n" +
                "     \n" +
                "     o IANA\n" +
                "     o RIR\n" +
                "     o NIR (There are no NIRs in the APNIC service region.)\n" +
                "     o LIR\n" +
                "     o WHITEPAGES\n" +
                "     o DIRECT_ASSIGNMENT\n" +
                "     o OTHER\n" +
                "     \n" +
                "         'IANA' for Internet Assigned Numbers Authority\n" +
                "         'RIR' for Regional Internet Registries\n" +
                "         'NIR' for National Internet Registries\n" +
                "         'LIR' for Local Internet Registries\n" +
                "         'WHITEPAGES' for special links to industry people\n" +
                "         'DIRECT_ASSIGNMENT' for direct contract with APNIC\n" +
                "         'OTHER' for all other organisations.\n" +
                "\n"));

    }

}
