package net.apnic.db.whois.api.whois;

import net.apnic.db.whois.common.IntegrationTest;
import net.ripe.db.whois.api.AbstractIntegrationTest;
import net.ripe.db.whois.api.MailUpdatesTestSupport;
import net.ripe.db.whois.common.profiles.WhoisVariant;
import net.ripe.db.whois.common.rpsl.RpslObject;
import net.ripe.db.whois.update.domain.UpdateMessages;
import net.ripe.db.whois.update.mail.MailSenderStub;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.ActiveProfiles;

import javax.mail.internet.MimeMessage;

import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertThat;

@Category(IntegrationTest.class)
@ActiveProfiles( {"TEST", WhoisVariant.WHOIS_VARIANT_APNIC} )
public class MailUpdatesServiceTestIntegration extends AbstractIntegrationTest {

    private static final RpslObject OWNER_MNT = RpslObject.parse("" +
            "mntner:      OWNER-MNT\n" +
            "descr:       Owner Maintainer\n" +
            "admin-c:     TP1-TEST\n" +
            "upd-to:      noreply@apnic.net\n" +
            "auth:        MD5-PW $1$d9fKeTr2$Si7YudNf4rUGmR71n/cqk/ #test\n" +
            "mnt-by:      OWNER-MNT\n" +
            "referral-by: OWNER-MNT\n" +
            "changed:     dbtest@apnic.net 20120101\n" +
            "source:      TEST");

    private static final RpslObject TEST_PERSON = RpslObject.parse("" +
            "person:  Test Person\n" +
            "address: Brisbane Queen St Mall\n" +
            "phone:   +61 7 33445566\n" +
            "nic-hdl: TP1-TEST\n" +
            "mnt-by:  OWNER-MNT\n" +
            "changed: dbtest@apnic.net 20120101\n" +
            "source:  TEST\n");

    private static final String DS_RDATA_A = "ds-rdata: 52151 1 1 13ee60f7499a70e5aadaf05828e7fc59e8e70bc1\n";
    private static final String DS_RDATA_B = "ds-rdata: 52151 1 1 23ee60f7499a70e5aadaf05828e7fc59e8e70bc2\n";

    private static final String DOM_DS_RDATA_0_ENTRIES = "domain: 29.12.202.in-addr.arpa\n";
    private static final String DOM_DS_RDATA_1_ENTRIES = "domain: 30.12.202.in-addr.arpa\n";
    private static final String DOM_DS_RDATA_2_ENTRIES = "domain: 31.12.202.in-addr.arpa\n";

    private static final String EMAIL_STATIC_DOMAIN = "" +
            "descr:           Description\n" +
            "admin-c:         TP1-TEST\n" +
            "tech-c:          TP1-TEST\n" +
            "zone-c:          TP1-TEST\n" +
            "notify:          notify@test.net.au\n" +
            "nserver:         ns1.test.com.au\n" +
            "nserver:         ns2.test.com.au\n" +
            "changed:         test@test.net.au 20010816\n" +
            "changed:         test@test.net.au 20121121\n" +
            "source:          TEST\n" +
            "password:        test\n" +
            "mnt-by:          OWNER-MNT\n";

    @Autowired MailUpdatesTestSupport mailUpdatesTestSupport;
    @Autowired MailSenderStub mailSenderStub;

    @Before
    public void setup() throws Exception {
        databaseHelper.addObject("person: Test Person\nnic-hdl: TP1-TEST");
        databaseHelper.addObject(OWNER_MNT);
        databaseHelper.updateObject(TEST_PERSON);

        databaseHelper.addObject("" +
                "inetnum:        202.12.1.0 - 202.12.1.255\n" +
                "netname:        APNIC\n" +
                "descr:          Private Network\n" +
                "country:        NL\n" +
                "tech-c:         TP1-TEST\n" +
                "status:         ASSIGNED PA\n" +
                "mnt-by:         OWNER-MNT\n" +
                "mnt-lower:      OWNER-MNT\n" +
                "source:         TEST");

        databaseHelper.addObject("" +
                "inetnum:        202.12.2.0 - 202.12.2.255\n" +
                "netname:        APNIC\n" +
                "descr:          Private Network\n" +
                "country:        NL\n" +
                "tech-c:         TP1-TEST\n" +
                "status:         ASSIGNED PA\n" +
                "mnt-by:         OWNER-MNT\n" +
                "mnt-lower:      OWNER-MNT\n" +
                "source:         TEST");

        databaseHelper.addObject(DOM_DS_RDATA_0_ENTRIES + EMAIL_STATIC_DOMAIN);

        databaseHelper.addObject(DOM_DS_RDATA_1_ENTRIES + DS_RDATA_A + EMAIL_STATIC_DOMAIN);

        databaseHelper.addObject(DOM_DS_RDATA_2_ENTRIES + DS_RDATA_A + DS_RDATA_B + EMAIL_STATIC_DOMAIN);

        ipTreeUpdater.rebuild();
    }

    @Test
    public void mail_add_domain_with_no_ds_rdata() throws Exception {
        final String response = mailUpdatesTestSupport.insert("NEW",
                "domain: 1.12.202.in-addr.arpa\n" +
                 EMAIL_STATIC_DOMAIN);
        final MimeMessage message = mailSenderStub.getMessage(response);
        assertThat(message.getContent().toString(), containsString("Create SUCCEEDED:"));
    }

    @Test
    public void mail_add_domain_with_ds_rdata() throws Exception {
        final String response = mailUpdatesTestSupport.insert("NEW",
                 "domain: 2.12.202.in-addr.arpa\n" +
                  DS_RDATA_A  +
                  EMAIL_STATIC_DOMAIN);
        final MimeMessage message = mailSenderStub.getMessage(response);
        assertThat(message.getContent().toString(), containsString(UpdateMessages.attributeDsRdataCannotBeModified().toString()));
    }

    @Test
    public void mail_update_with_matching_ds_rdata() throws Exception {
        final String response = mailUpdatesTestSupport.insert("", DOM_DS_RDATA_1_ENTRIES + DS_RDATA_A + EMAIL_STATIC_DOMAIN);
        final MimeMessage message = mailSenderStub.getMessage(response);
        assertThat(message.getContent().toString(), containsString("Modify SUCCEEDED:"));
    }

    @Test
    public void mail_update_with_matching_multiple_ds_rdata() throws Exception {
        final String response = mailUpdatesTestSupport.insert("", DOM_DS_RDATA_2_ENTRIES + DS_RDATA_A +  DS_RDATA_B + EMAIL_STATIC_DOMAIN);
        final MimeMessage message = mailSenderStub.getMessage(response);
        assertThat(message.getContent().toString(), containsString("Modify SUCCEEDED:"));
    }


    @Test
    public void mail_update_with_matching_multiple_outoforder_ds_rdata() throws Exception {
        final String response = mailUpdatesTestSupport.insert("", DOM_DS_RDATA_2_ENTRIES + DS_RDATA_B + DS_RDATA_A + EMAIL_STATIC_DOMAIN);
        final MimeMessage message = mailSenderStub.getMessage(response);
        assertThat(message.getContent().toString(), containsString("Modify SUCCEEDED:"));
    }

    @Test
    public void mail_update_with_original_having_ds_rdata() throws Exception {
        final String response = mailUpdatesTestSupport.insert("", DOM_DS_RDATA_1_ENTRIES + EMAIL_STATIC_DOMAIN);
        final MimeMessage message = mailSenderStub.getMessage(response);
        assertThat(message.getContent().toString(), containsString(UpdateMessages.attributeDsRdataCannotBeModified().toString()));
    }

    @Test
    public void mail_update_with_update_having_ds_rdata() throws Exception {
        final String response = mailUpdatesTestSupport.insert("", DOM_DS_RDATA_0_ENTRIES + DS_RDATA_A + EMAIL_STATIC_DOMAIN );
        final MimeMessage message = mailSenderStub.getMessage(response);
        assertThat(message.getContent().toString(), containsString(UpdateMessages.attributeDsRdataCannotBeModified().toString()));
    }

    @Test
    public void mail_update_with_update_having_different_ds_rdata() throws Exception {
        final String response = mailUpdatesTestSupport.insert("", DOM_DS_RDATA_1_ENTRIES + DS_RDATA_B + EMAIL_STATIC_DOMAIN );
        final MimeMessage message = mailSenderStub.getMessage(response);
        assertThat(message.getContent().toString(), containsString(UpdateMessages.attributeDsRdataCannotBeModified().toString()));
    }
}
