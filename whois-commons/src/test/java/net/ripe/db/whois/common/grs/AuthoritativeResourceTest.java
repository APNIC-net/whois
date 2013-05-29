package net.ripe.db.whois.common.grs;

import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.RpslObject;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;

import java.io.File;
import java.io.IOException;
import java.util.Scanner;
import java.util.zip.GZIPInputStream;

import static net.ripe.db.whois.common.domain.CIString.ciString;
import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

@RunWith(MockitoJUnitRunner.class)
public class AuthoritativeResourceTest {
    Logger logger = LoggerFactory.getLogger(AuthoritativeResourceTest.class);
    @Rule public TemporaryFolder folder = new TemporaryFolder();

    @Test(expected = IllegalArgumentException.class)
    public void unknown_file() throws IOException {
        AuthoritativeResource.loadFromFile(logger, "unknown", new File(folder.getRoot(), "unknown"));
    }

    @Test
    public void empty_file() throws IOException {
        final AuthoritativeResource resourceData = AuthoritativeResource.loadFromFile(logger, "RIPE-GRS", folder.newFile());
        assertThat(resourceData.getNrAutNums(), is(0));
        assertThat(resourceData.getNrInetnums(), is(0));
        assertThat(resourceData.getNrInet6nums(), is(0));
        assertThat(resourceData.isEmpty(), is(true));
    }

    @Test
    public void load_apnic() throws IOException {
        final AuthoritativeResource resourceData = AuthoritativeResource.loadFromScanner(logger, "APNIC-GRS", getScanner("delegated-apnic-extended-latest"));
        assertThat(resourceData.getNrAutNums(), is(8625));
        assertThat(resourceData.getNrInetnums(), is(21587));
        assertThat(resourceData.getNrInet6nums(), is(2897));
        assertThat(resourceData.isEmpty(), is(false));
    }

    @Test
    public void load_unexpected_source() throws IOException {
        final AuthoritativeResource resourceData = AuthoritativeResource.loadFromScanner(logger, "TEST-GRS", new Scanner("" +
                "ripencc|EU|asn|7|1|19930901|allocated\n" +
                "ripencc|EU|asn|28|10|19930901|allocated\n" +
                "ripencc|FR|ipv4|2.0.0.0|1048576|20100712|allocated\n" +
                "ripencc|EU|ipv4|2.16.0.0|524288|20100910|allocated\n" +
                "ripencc|DE|ipv6|2001:608::|32|19990812|allocated\n" +
                "ripencc|NL|ipv6|2001:610::|32|19990819|allocated\n"));

        assertThat(resourceData.getNrAutNums(), is(0));
        assertThat(resourceData.getNrInetnums(), is(0));
        assertThat(resourceData.getNrInet6nums(), is(0));
        assertThat(resourceData.isEmpty(), is(true));
    }

    @Test
    public void load_ripe() throws IOException {
        final AuthoritativeResource resourceData = AuthoritativeResource.loadFromScanner(logger, "RIPE-GRS", getScanner("delegated-ripencc-extended-latest"));
        assertThat(resourceData.getNrAutNums(), is(25412));
        assertThat(resourceData.getNrInetnums(), is(49125));
        assertThat(resourceData.getNrInet6nums(), is(6912));
        assertThat(resourceData.isEmpty(), is(false));
    }

    @Test
    public void load_country_ignored() {
        final AuthoritativeResource resourceData = AuthoritativeResource.loadFromScanner(logger, "RIPE-GRS", new Scanner("" +
                "ripencc|*|asn|7|1|19930901|allocated\n" +
                "ripencc|EU|asn|28|1|19930901|allocated\n"));

        assertThat(resourceData.getNrAutNums(), is(1));
        assertThat(resourceData.isMaintainedInRirSpace(RpslObject.parse("aut-num: AS7")), is(false));
        assertThat(resourceData.isMaintainedInRirSpace(RpslObject.parse("aut-num: AS28")), is(true));
        assertThat(resourceData.isEmpty(), is(false));
    }

    @Test
    public void load_type_unexpected() {
        final AuthoritativeResource resourceData = AuthoritativeResource.loadFromScanner(logger, "RIPE-GRS", new Scanner("" +
                "ripencc|EU|nsa|7|1|19930901|allocated\n" +
                "ripencc|EU|asn|28|1|19930901|allocated\n"));

        assertThat(resourceData.getNrAutNums(), is(1));
        assertThat(resourceData.isMaintainedInRirSpace(RpslObject.parse("aut-num: AS7")), is(false));
        assertThat(resourceData.isMaintainedInRirSpace(RpslObject.parse("aut-num: AS28")), is(true));
        assertThat(resourceData.isEmpty(), is(false));
    }

    @Test
    public void load_start_invalid() {
        final AuthoritativeResource resourceData = AuthoritativeResource.loadFromScanner(logger, "RIPE-GRS", new Scanner("" +
                "ripencc|EU|asn|a|1|19930901|allocated\n" +
                "ripencc|EU|asn|28|1|19930901|allocated\n"));

        assertThat(resourceData.getNrAutNums(), is(1));
        assertThat(resourceData.isMaintainedInRirSpace(RpslObject.parse("aut-num: AS7")), is(false));
        assertThat(resourceData.isMaintainedInRirSpace(RpslObject.parse("aut-num: AS28")), is(true));
        assertThat(resourceData.isEmpty(), is(false));
    }

    @Test
    public void isMaintainedInRirSpace_empty_file() {
        final AuthoritativeResource resourceData = AuthoritativeResource.loadFromScanner(logger, "RIPE-GRS", new Scanner(""));
        assertThat(resourceData.isMaintainedInRirSpace(RpslObject.parse("aut-num: AS123")), is(false));
        assertThat(resourceData.isMaintainedInRirSpace(RpslObject.parse("inetnum: 10.0.0.0 - 10.255.255.255")), is(false));
        assertThat(resourceData.isMaintainedInRirSpace(RpslObject.parse("inet6num: 2001::/20")), is(false));
        assertThat(resourceData.isEmpty(), is(true));
    }

    @Test
    public void isMaintainedByRir_empty_file() {
        final AuthoritativeResource resourceData = AuthoritativeResource.loadFromScanner(logger, "RIPE-GRS", new Scanner(""));
        assertThat(resourceData.isMaintainedByRir(ObjectType.AUT_NUM, ciString("AS123")), is(false));
        assertThat(resourceData.isMaintainedByRir(ObjectType.INETNUM, ciString("10.0.0.0 - 10.255.255.255")), is(false));
        assertThat(resourceData.isMaintainedByRir(ObjectType.INET6NUM, ciString("2001::/20")), is(false));
    }

    @Test
    public void isMaintainedInRirSpace_invalid_resource() {
        final AuthoritativeResource resourceData = AuthoritativeResource.loadFromScanner(logger, "RIPE-GRS", new Scanner(""));
        assertThat(resourceData.isMaintainedInRirSpace(RpslObject.parse("aut-num: 12345")), is(false));
        assertThat(resourceData.isMaintainedInRirSpace(RpslObject.parse("inetnum: 0")), is(false));
        assertThat(resourceData.isMaintainedInRirSpace(RpslObject.parse("inet6num: 0")), is(false));
        assertThat(resourceData.isEmpty(), is(true));
    }

    @Test
    public void isMaintainedByRir_invalid_resource() {
        final AuthoritativeResource resourceData = AuthoritativeResource.loadFromScanner(logger, "RIPE-GRS", new Scanner(""));
        assertThat(resourceData.isMaintainedByRir(ObjectType.AUT_NUM, ciString("12345")), is(false));
        assertThat(resourceData.isMaintainedByRir(ObjectType.INETNUM, ciString("0")), is(false));
        assertThat(resourceData.isMaintainedByRir(ObjectType.INET6NUM, ciString("0")), is(false));
    }

    @Test
    public void isMaintainedInRirSpace_no_resource() {
        final AuthoritativeResource resourceData = AuthoritativeResource.loadFromScanner(logger, "RIPE-GRS", new Scanner(""));
        assertThat(resourceData.isMaintainedInRirSpace(RpslObject.parse("mntner: DEV-MNT")), is(true));
        assertThat(resourceData.isMaintainedInRirSpace(RpslObject.parse("person: Test Person\nnic-hdl: TP1-TEST")), is(true));
        assertThat(resourceData.isMaintainedInRirSpace(RpslObject.parse("organisation: ORG-TOL1-TEST")), is(true));
        assertThat(resourceData.isEmpty(), is(true));
    }

    @Test
    public void isMaintainedByRir_no_resource() {
        final AuthoritativeResource resourceData = AuthoritativeResource.loadFromScanner(logger, "RIPE-GRS", new Scanner(""));
        assertThat(resourceData.isMaintainedByRir(ObjectType.MNTNER, ciString("12345")), is(true));
        assertThat(resourceData.isMaintainedByRir(ObjectType.PERSON, ciString("0")), is(true));
        assertThat(resourceData.isMaintainedByRir(ObjectType.ORGANISATION, ciString("0")), is(true));
    }

    @Test
    public void isMaintainedInRirSpace_aut_num() {
        final AuthoritativeResource resourceData = AuthoritativeResource.loadFromScanner(logger, "RIPE-GRS", new Scanner("" +
                "ripencc|EU|asn|7|1|19930901|allocated\n" +
                "ripencc|EU|asn|28|10|19930901|allocated\n"));

        assertThat(resourceData.isMaintainedInRirSpace(RpslObject.parse("aut-num: AS6")), is(false));
        assertThat(resourceData.isMaintainedInRirSpace(RpslObject.parse("aut-num: AS7")), is(true));
        assertThat(resourceData.isMaintainedInRirSpace(RpslObject.parse("aut-num: AS8")), is(false));

        assertThat(resourceData.isMaintainedInRirSpace(RpslObject.parse("aut-num: AS27")), is(false));
        assertThat(resourceData.isMaintainedInRirSpace(RpslObject.parse("aut-num: AS28")), is(true));
        assertThat(resourceData.isMaintainedInRirSpace(RpslObject.parse("aut-num: AS29")), is(true));
        assertThat(resourceData.isMaintainedInRirSpace(RpslObject.parse("aut-num: AS37")), is(true));
        assertThat(resourceData.isMaintainedInRirSpace(RpslObject.parse("aut-num: AS38")), is(false));
        assertThat(resourceData.isEmpty(), is(false));
    }

    @Test
    public void isMaintainedByRir_aut_num() {
        final AuthoritativeResource resourceData = AuthoritativeResource.loadFromScanner(logger, "RIPE-GRS", new Scanner("" +
                "ripencc|EU|asn|7|1|19930901|allocated\n" +
                "ripencc|EU|asn|28|10|19930901|allocated\n"));

        assertThat(resourceData.isMaintainedByRir(ObjectType.AUT_NUM, ciString("AS6")), is(false));
        assertThat(resourceData.isMaintainedByRir(ObjectType.AUT_NUM, ciString("AS7")), is(true));
        assertThat(resourceData.isMaintainedByRir(ObjectType.AUT_NUM, ciString("AS8")), is(false));

        assertThat(resourceData.isMaintainedByRir(ObjectType.AUT_NUM, ciString("AS27")), is(false));
        assertThat(resourceData.isMaintainedByRir(ObjectType.AUT_NUM, ciString("AS28")), is(true));
        assertThat(resourceData.isMaintainedByRir(ObjectType.AUT_NUM, ciString("AS29")), is(true));
        assertThat(resourceData.isMaintainedByRir(ObjectType.AUT_NUM, ciString("AS37")), is(true));
        assertThat(resourceData.isMaintainedByRir(ObjectType.AUT_NUM, ciString("AS38")), is(false));
    }

    @Test
    public void isMaintainedInRirSpace_ipv4() {
        final AuthoritativeResource resourceData = AuthoritativeResource.loadFromScanner(logger, "RIPE-GRS", new Scanner("" +
                "ripencc|FR|ipv4|2.0.0.0|1048576|20100712|allocated\n" +
                "ripencc|EU|ipv4|2.16.0.0|524288|20100910|allocated\n"));

        assertThat(resourceData.isMaintainedInRirSpace(RpslObject.parse("inetnum: 1.0.0.0 - 1.255.255.255")), is(false));
        assertThat(resourceData.isMaintainedInRirSpace(RpslObject.parse("inetnum: 2.0.0.0 - 2.0.0.0")), is(true));
        assertThat(resourceData.isMaintainedInRirSpace(RpslObject.parse("inetnum: 2.0.0.0 - 2.0.0.1")), is(true));
        assertThat(resourceData.isMaintainedInRirSpace(RpslObject.parse("inetnum: 2.0.0.1 - 2.0.0.1")), is(true));
        assertThat(resourceData.isMaintainedInRirSpace(RpslObject.parse("inetnum: 2/12")), is(true));
        assertThat(resourceData.isMaintainedInRirSpace(RpslObject.parse("inetnum: 2/19")), is(true));
        assertThat(resourceData.isMaintainedInRirSpace(RpslObject.parse("inetnum: 2/11")), is(false));
        assertThat(resourceData.isEmpty(), is(false));
    }

    @Test
    public void isMaintainedByRir_ipv4() {
        final AuthoritativeResource resourceData = AuthoritativeResource.loadFromScanner(logger, "RIPE-GRS", new Scanner("" +
                "ripencc|FR|ipv4|2.0.0.0|1048576|20100712|allocated\n" +
                "ripencc|EU|ipv4|2.16.0.0|524288|20100910|allocated\n"));

        assertThat(resourceData.isMaintainedByRir(ObjectType.INETNUM, ciString("1.0.0.0 - 1.255.255.255")), is(false));
        assertThat(resourceData.isMaintainedByRir(ObjectType.INETNUM, ciString("2.0.0.0 - 2.0.0.0")), is(false));
        assertThat(resourceData.isMaintainedByRir(ObjectType.INETNUM, ciString("2.0.0.0 - 2.0.0.1")), is(false));
        assertThat(resourceData.isMaintainedByRir(ObjectType.INETNUM, ciString("2.0.0.1 - 2.0.0.1")), is(false));
        assertThat(resourceData.isMaintainedByRir(ObjectType.INETNUM, ciString("2/12")), is(true));
        assertThat(resourceData.isMaintainedByRir(ObjectType.INETNUM, ciString("2/19")), is(false));
        assertThat(resourceData.isMaintainedByRir(ObjectType.INETNUM, ciString("2/11")), is(false));
    }

    @Test
    public void isMaintainedInRirSpace_ipv6() {
        final AuthoritativeResource resourceData = AuthoritativeResource.loadFromScanner(logger, "RIPE-GRS", new Scanner("" +
                "ripencc|DE|ipv6|2001:608::|32|19990812|allocated\n" +
                "ripencc|NL|ipv6|2001:610::|32|19990819|allocated\n"));

        assertThat(resourceData.isMaintainedInRirSpace(RpslObject.parse("inet6num: 2001::")), is(false));
        assertThat(resourceData.isMaintainedInRirSpace(RpslObject.parse("inet6num: 2002:608::")), is(false));
        assertThat(resourceData.isMaintainedInRirSpace(RpslObject.parse("inet6num: 2001:608::")), is(true));
        assertThat(resourceData.isMaintainedInRirSpace(RpslObject.parse("inet6num: 2001:608:abcd::")), is(true));
        assertThat(resourceData.isEmpty(), is(false));
    }

    @Test
    public void isMaintainedByRir_ipv6() {
        final AuthoritativeResource resourceData = AuthoritativeResource.loadFromScanner(logger, "RIPE-GRS", new Scanner("" +
                "ripencc|DE|ipv6|2001:608::|32|19990812|allocated\n" +
                "ripencc|NL|ipv6|2001:610::|32|19990819|allocated\n"));

        assertThat(resourceData.isMaintainedByRir(ObjectType.INET6NUM, ciString("2001::")), is(false));
        assertThat(resourceData.isMaintainedByRir(ObjectType.INET6NUM, ciString("2002:608::")), is(false));
        assertThat(resourceData.isMaintainedByRir(ObjectType.INET6NUM, ciString("2001:608::/32")), is(true));
        assertThat(resourceData.isMaintainedByRir(ObjectType.INET6NUM, ciString("2001:608:abcd::")), is(false));
        assertThat(resourceData.isEmpty(), is(false));
    }

    @Test
    public void isMaintainedInRirSpace_unknown_data() {
        final AuthoritativeResource resourceData = AuthoritativeResource.unknown(logger);
        assertThat(resourceData.isMaintainedInRirSpace(RpslObject.parse("aut-num: AS6")), is(false));
        assertThat(resourceData.isMaintainedInRirSpace(RpslObject.parse("inetnum: 1.0.0.0 - 1.255.255.255")), is(false));
        assertThat(resourceData.isMaintainedInRirSpace(RpslObject.parse("inet6num: 2001::")), is(false));
        assertThat(resourceData.isEmpty(), is(true));
    }

    @Test
    public void isMaintainedByRir_unknown_data() {
        final AuthoritativeResource resourceData = AuthoritativeResource.unknown(logger);
        assertThat(resourceData.isMaintainedByRir(ObjectType.AUT_NUM, ciString("AS6")), is(false));
        assertThat(resourceData.isMaintainedByRir(ObjectType.INETNUM, ciString("1.0.0.0 - 1.255.255.255")), is(false));
        assertThat(resourceData.isMaintainedByRir(ObjectType.INET6NUM, ciString("2001::")), is(false));
        assertThat(resourceData.isEmpty(), is(true));
    }

    @Test
    public void getResources_unknown() {
        assertThat(AuthoritativeResource.unknown(logger).getResourceTypes(),
                containsInAnyOrder(ObjectType.AUT_NUM, ObjectType.INETNUM, ObjectType.INET6NUM));
    }

    @Test
    public void getResources_scanner() {
        assertThat(AuthoritativeResource.loadFromScanner(logger, "RIPE-GRS", new Scanner("")).getResourceTypes(),
                containsInAnyOrder(ObjectType.AUT_NUM, ObjectType.INETNUM, ObjectType.INET6NUM));
    }

    private Scanner getScanner(final String resourceName) throws IOException {
        final Resource resource = new ClassPathResource(String.format("grs/%s.gz", resourceName));
        return new Scanner(new GZIPInputStream(resource.getInputStream()));
    }
}