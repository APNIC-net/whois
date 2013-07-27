package net.ripe.db.whois.api.whois.rdap;

import net.ripe.db.whois.api.whois.rdap.domain.Entity;
import net.ripe.db.whois.common.rpsl.RpslObject;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertThat;

public class NoticeFactoryTest {
    private static final Logger LOGGER = LoggerFactory.getLogger(NoticeFactoryTest.class);

    @Test
    public void notices_test() throws Exception {
        RpslObject rpslObject = RpslObject.parse("" +
                "person:        First Last\n" +
                "descr:         descr1\n" +
                "descr:         descr2\n" +
                "descr:         descr2\n" +
                "descr:         descr1\n" +
                "address:       Singel 258\n" +
                "phone:         +31 20 123456\n" +
                "nic-hdl:       FL1-TEST\n" +
                "remarks:       remark1\n" +
                "remarks:       remark2\n" +
                "remarks:       remark2\n" +
                "remarks:       remark1\n" +
                "mnt-by:        TST-MNT\n" +
                "changed:       first@last.org 20120220\n" +
                "source:        TEST");

        Entity entity = new Entity();
        entity.getNotices().addAll(NoticeFactory.generateObjectNotices(rpslObject, "http://selfurl"));

        String json = RdapHelperUtils.marshal(entity);
        assertThat(json, equalTo("" +
                "{\n" +
                "  \"notices\" : [ {\n" +
                "    \"title\" : \"Terms and Conditions\",\n" +
                "    \"description\" : [ \"This is the RIPE Database query service. The objects are in RDAP format.\" ],\n" +
                "    \"links\" : [ {\n" +
                "      \"value\" : \"http://selfurl\",\n" +
                "      \"rel\" : \"terms-of-service\",\n" +
                "      \"href\" : \"http://www.ripe.net/db/support/db-terms-conditions.pdf\",\n" +
                "      \"type\" : \"application/pdf\"\n" +
                "    } ]\n" +
                "  }, {\n" +
                "    \"title\" : \"Filtered\",\n" +
                "    \"description\" : [ \"This output has been filtered.\" ]\n" +
                "  }, {\n" +
                "    \"title\" : \"Source\",\n" +
                "    \"description\" : [ \"Objects returned came from source\", \"TEST\" ]\n" +
                "  } ]\n" +
                "}"));

        Entity entityDeser = RdapHelperUtils.unmarshal(json, Entity.class);


    }

}
