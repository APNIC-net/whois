package net.ripe.db.whois.api.whois.rdap;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.fge.jackson.JsonLoader;
import com.github.fge.jsonschema.exceptions.ProcessingException;
import com.github.fge.jsonschema.main.JsonSchema;
import com.github.fge.jsonschema.main.JsonSchemaFactory;
import com.github.fge.jsonschema.report.ProcessingReport;
import com.google.common.base.Joiner;
import com.google.common.collect.Lists;
import net.ripe.db.whois.api.whois.rdap.domain.Autnum;
import net.ripe.db.whois.api.whois.rdap.domain.Domain;
import net.ripe.db.whois.api.whois.rdap.domain.Entity;
import net.ripe.db.whois.api.whois.rdap.domain.Ip;
import net.ripe.db.whois.common.ManualTest;
import net.ripe.db.whois.common.domain.Ipv4Resource;
import net.ripe.db.whois.common.domain.Ipv6Resource;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpStatus;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URL;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

@Category(ManualTest.class)
public class RdapRegressionTestIntegration {
    private static Class clazz = RdapRegressionTestIntegration.class;
    private static final Logger LOGGER = LoggerFactory.getLogger(clazz);

    private static final String PKGBASE  = '/' + clazz.getPackage().getName().replace(".", "/");

    // Limit the number of queries for each rdap type ( -1 no limit )
    private static final int PROCESS_MAX_QUERIES = 3;

    private final static JsonSchemaFactory factory = JsonSchemaFactory.byDefault();

    private static String resourcePath = "/" + clazz.getName().replace(".", "/");
    private static Properties testProperties;
    private static JsonSchema rdapJsonSchema;

    private static URL rdap_server_url_base;
    private static String db_driver;
    private static String db_url;
    private static String db_username;
    private static String db_password;
    private static HttpClient client;

    // Run query to pull back all entity rdap urls
    // http://*/entity
    // 10 - person
    // 11 - role
    // 17 - irt
    // 18 - org
    private static final Pair<String, List<Integer>> entities = new Pair<String, List<Integer>>("entity", Lists.newArrayList(10, 11, 17, 18));

    // http://*/domain
    // 3 - domain
    private static final Pair<String, List<Integer>> domains = new Pair<String, List<Integer>>("domain", Lists.newArrayList(3));

    // http://*/autnum
    // 2 - aut-num
    private static final Pair<String, List<Integer>> autnums = new Pair<String, List<Integer>>("autnum", Lists.newArrayList(2));

    // http://*/ip
    // 6 - inetnum
    // 5 - inetnum
    private static final Pair<String, List<Integer>> ips = new Pair<String, List<Integer>>("ip", Lists.newArrayList(5, 6));

    @BeforeClass
    public static void setUp() throws Exception {
        client = new HttpClient();
        // Load properties
        testProperties = new Properties();
        testProperties.load(clazz.getResourceAsStream(resourcePath + ".properties"));

        // Assign
        rdap_server_url_base = new URL(testProperties.getProperty("rdap_server_url_base"));
        db_driver = testProperties.getProperty("db_driver");
        db_url = testProperties.getProperty("db_url");
        db_username = testProperties.getProperty("db_username");
        db_password = testProperties.getProperty("db_password");

        try {
            rdapJsonSchema = factory.getJsonSchema(JsonLoader.fromResource(PKGBASE + "/rdap.schema.json"));
        } catch (Exception ex) {
            LOGGER.error("Could not load rdap json schema", ex);
        }

        // Test the rdap http server is reachable
        //byte[] content = RdapHelperUtils.getHttpContent(rdap_server_url_base.toString(), true).body;
    }

    @Test
    public void validate_all_rdap_entities_test() throws Exception {
        String type = entities.getKey();
        List<String> pkeys = runRdapQuery(entities.getValue());
        LOGGER.info(type + " query size=" + pkeys.size());

        String prefix = rdap_server_url_base.toString() + "/" + type + "/";

        int cnt = 0;
        // For each url : call each url
        for (String pkey : pkeys) {
            if (cnt++ >= PROCESS_MAX_QUERIES && PROCESS_MAX_QUERIES >= 0) {
                break;
            }

            String url = String.format("%s%s",prefix,pkey);
            try {
                RdapHelperUtils.HttpResponseElements result = RdapHelperUtils.getHttpHeaderAndContent(url, true);
                String response = new String(result.body);
                int statusCode = result.statusCode;

                if (statusCode == HttpStatus.SC_OK) {
                    if (LOGGER.isDebugEnabled()) LOGGER.debug(response);
                    Entity entity = RdapHelperUtils.unmarshal(response, Entity.class);

                    // Manual validation checks / sanity checks

                } else {
                    net.ripe.db.whois.api.whois.rdap.domain.Error error = RdapHelperUtils.unmarshal(response, net.ripe.db.whois.api.whois.rdap.domain.Error.class);
                    LOGGER.error(url + ":" + response);
                }
                validateJson(url, response);


            } catch (Throwable ex) {
                LOGGER.error("Failed to unmarshal rdap response [" + url + "]", ex);
            }

        }
    }

    private boolean validateJson(String url, String response) throws IOException, ProcessingException {
        // Validate against json schema
        final JsonNode json = JsonLoader.fromString(response);
        ProcessingReport report = rdapJsonSchema.validate(json);
        if (!report.isSuccess()) {
            LOGGER.error(String.format("Schema validation failed [%s][%s]",url, report));
        }
        return report.isSuccess();
    }


    @Test
    public void validate_all_rdap_domains_test() throws Exception {
        String type = domains.getKey();
        List<String> pkeys = runRdapQuery(domains.getValue());
        LOGGER.info(type + " query size=" + pkeys.size());

        String prefix = rdap_server_url_base.toString() + "/" + type + "/";

        int cnt = 0;
        // For each url : call each url
        for (String pkey : pkeys) {
            if (cnt++ >= PROCESS_MAX_QUERIES && PROCESS_MAX_QUERIES >= 0) {
                break;
            }

            String url = String.format("%s%s", prefix, pkey);
            try {
                RdapHelperUtils.HttpResponseElements result = RdapHelperUtils.getHttpHeaderAndContent(url, true);
                String response = new String(result.body);
                int statusCode = result.statusCode;

                if (statusCode == HttpStatus.SC_OK) {
                    if (LOGGER.isDebugEnabled()) LOGGER.debug(response);
                    Domain domain = RdapHelperUtils.unmarshal(response, Domain.class);

                    // Manual validation checks / sanity checks

                } else {
                    net.ripe.db.whois.api.whois.rdap.domain.Error error = RdapHelperUtils.unmarshal(response, net.ripe.db.whois.api.whois.rdap.domain.Error.class);
                    LOGGER.error(url + ":" + response);
                }

                validateJson(url, response);

            } catch (Throwable ex) {
                LOGGER.error("Failed to unmarshal rdap response [" + url + "]", ex);
            }
        }

    }

    @Test
    public void validate_all_rdap_autnums_test() throws Exception {
        String type = autnums.getKey();
        List<String> urls = runRdapQuery("select concat('" + rdap_server_url_base.toString() + "/" + type + "/' , trim(substring(pkey, 3, 50)) ) from last where object_type in (" +
                Joiner.on(",").join(autnums.getValue()) + ") and pkey like 'AS%';");
        LOGGER.info(type + " query size=" + urls.size());

        int cnt = 0;
        // For each url : call each url
        for (String url : urls) {
            if (cnt++ >= PROCESS_MAX_QUERIES && PROCESS_MAX_QUERIES >= 0) {
                break;
            }
            try {
                RdapHelperUtils.HttpResponseElements result = RdapHelperUtils.getHttpHeaderAndContent(url, true);
                String response = new String(result.body);
                int statusCode = result.statusCode;

                if (statusCode == HttpStatus.SC_OK) {
                    if (LOGGER.isDebugEnabled()) LOGGER.debug(response);
                    Autnum autnum = RdapHelperUtils.unmarshal(response, Autnum.class);

                    // Manual validation checks / sanity checks

                } else {
                    net.ripe.db.whois.api.whois.rdap.domain.Error error = RdapHelperUtils.unmarshal(response, net.ripe.db.whois.api.whois.rdap.domain.Error.class);
                    LOGGER.error(url + ":" + response);
                }

                validateJson(url, response);

            } catch (Throwable ex) {
                LOGGER.error("Failed to unmarshal rdap response [" + url + "]", ex);
            }

        }
    }

    @Test
    public void validate_all_rdap_ips_test() throws Exception {
        String type = ips.getKey();
        List<String> pkeys = runRdapQuery(ips.getValue());
        LOGGER.info(type + " query size=" + pkeys.size());

        String prefix = rdap_server_url_base.toString() + "/" + type + "/";

        int cnt = 0;
        // For each url : call each url
        for (String pkey : pkeys) {
            if (cnt++ >= PROCESS_MAX_QUERIES && PROCESS_MAX_QUERIES >= 0) {
                break;
            }

            // ip query result needs to be converted
            String postfix = pkey.indexOf(":") > 0 ? Ipv6Resource.parse(pkey).toString() : Ipv4Resource.parse(pkey).toString();
            if (postfix.indexOf("-") >= 0) {
                LOGGER.warn("Cannot query ip range:" + postfix);
                continue;
            }
            String url = String.format("%s%s", prefix, postfix);

            try {
                RdapHelperUtils.HttpResponseElements result = RdapHelperUtils.getHttpHeaderAndContent(url, true);
                String response = new String(result.body);
                int statusCode = result.statusCode;

                if (statusCode == HttpStatus.SC_OK) {
                    if (LOGGER.isDebugEnabled()) LOGGER.debug(response);
                    Ip ip = RdapHelperUtils.unmarshal(response, Ip.class);

                    // Manual validation checks / sanity checks

                } else {
                    net.ripe.db.whois.api.whois.rdap.domain.Error error = RdapHelperUtils.unmarshal(response, net.ripe.db.whois.api.whois.rdap.domain.Error.class);
                    LOGGER.error(url + ":" + response);
                }

                validateJson(url, response);

            } catch (Throwable ex) {
                LOGGER.error("Failed to unmarshal rdap response [" + url + "]", ex);
            }
        }
    }

    @Test
    public void validate_rdap_manual_internal_test() throws Exception {
        final JsonNode autnum_json = JsonLoader.fromResource(PKGBASE + "/autnum.json");
        final JsonNode domain_json = JsonLoader.fromResource(PKGBASE + "/domain.json");
        final JsonNode entity_json = JsonLoader.fromResource(PKGBASE + "/entity.json");
        final JsonNode ip_json = JsonLoader.fromResource(PKGBASE + "/ip.json");

        ProcessingReport reportAutnum = rdapJsonSchema.validate(autnum_json);
        assert(reportAutnum.isSuccess());

        ProcessingReport reportDomain = rdapJsonSchema.validate(domain_json);
        assert(reportDomain.isSuccess());

        ProcessingReport reportEntity = rdapJsonSchema.validate(entity_json);
        assert(reportEntity.isSuccess());

        ProcessingReport reportIp = rdapJsonSchema.validate(ip_json);
        assert(reportIp.isSuccess());

    }

    @Test
    public void validate_rdap_manual_internal_fail_test() throws Exception {
        final JsonNode autnum_json = JsonLoader.fromResource(PKGBASE + "/autnum.bad.json");
        final JsonNode domain_json = JsonLoader.fromResource(PKGBASE + "/domain.bad.json");
        final JsonNode entity_json = JsonLoader.fromResource(PKGBASE + "/entity.bad.json");
        final JsonNode ip_json = JsonLoader.fromResource(PKGBASE + "/ip.bad.json");

        ProcessingReport reportAutnum = rdapJsonSchema.validate(autnum_json);
        assert(!reportAutnum.isSuccess());

        ProcessingReport reportDomain = rdapJsonSchema.validate(domain_json);
        assert(!reportDomain.isSuccess());

        ProcessingReport reportEntity = rdapJsonSchema.validate(entity_json);
        assert(!reportEntity.isSuccess());

        ProcessingReport reportIp = rdapJsonSchema.validate(ip_json);
        LOGGER.info(String.valueOf(reportIp));
        assert(!reportIp.isSuccess());

    }


    @Test
    public void validate_vcardArray_manual_internal_test() throws Exception {
        JsonSchema  vcardArrayJsonSchema = factory.getJsonSchema(JsonLoader.fromResource(PKGBASE + "/vcardArray.schema.json"));
        final JsonNode vcardArray_json = JsonLoader.fromResource(PKGBASE + "/vcardArray.json");

        ProcessingReport report = vcardArrayJsonSchema.validate(vcardArray_json);
        LOGGER.info(String.valueOf(report));
        assert(report.isSuccess());

    }

    @Test
    public void validate_vcard_manual_internal_test() throws Exception {
        JsonSchema  vcardJsonSchema = factory.getJsonSchema(JsonLoader.fromResource(PKGBASE + "/vcard.schema.json"));
        final JsonNode vcard_json = JsonLoader.fromResource(PKGBASE + "/vcard.json");

        ProcessingReport report = vcardJsonSchema.validate(vcard_json);
        LOGGER.info(String.valueOf(report));
        assert(report.isSuccess());

    }


    //@Test
    public void validate_rdap_manual_external_test() throws Exception {
        String url = "http://newwhois.tst.apnic.net/rdap/entity/HM20-AP";
        try {
            RdapHelperUtils.HttpResponseElements result = RdapHelperUtils.getHttpHeaderAndContent(url, true);
            String response = new String(result.body);
            int statusCode = result.statusCode;
            LOGGER.info("Response="+ response);
            if (statusCode == HttpStatus.SC_OK) {
                Entity entity = RdapHelperUtils.unmarshal(response, Entity.class);
            } else {
                net.ripe.db.whois.api.whois.rdap.domain.Error error = RdapHelperUtils.unmarshal(response, net.ripe.db.whois.api.whois.rdap.domain.Error.class);
            }
            validateJson(url, response);
        } catch (Throwable ex) {
            LOGGER.error("Failed to unmarshal rdap response [" + url + "]", ex);
        }
    }

    private static List<String> runRdapQuery(List<Integer> types) throws Exception {
        String query = "select pkey from last where object_type in (" + Joiner.on(",").join(types) + ");";
        return runQuery(query);
    }

    private static List<String> runRdapQuery(String query) throws Exception {
        return runQuery(query);
    }

    private static List<String> runQuery(String query) throws ClassNotFoundException, SQLException {
        List<String> queries = new ArrayList<>();
        Connection connection = null;
        Statement statement = null;
        ResultSet rs = null;
        try {
            // Load queries from the db
            Class.forName(db_driver);
            connection = DriverManager.getConnection(db_url, db_username, db_password);
            statement = connection.createStatement();
            rs = statement.executeQuery(query);
            while (rs.next()) {
                //Retrieve by column name
                queries.add(rs.getString(1));
            }
        } finally {
            try {
                if (rs != null) {
                    rs.close();
                }
            } catch (SQLException sex) {
            }
            try {
                if (statement != null) {
                    statement.close();
                }
            } catch (SQLException sex) {
            }
            try {
                if (connection != null) {
                    connection.close();
                }
            } catch (SQLException sex) {
            }
        }

        return queries;
    }

}
