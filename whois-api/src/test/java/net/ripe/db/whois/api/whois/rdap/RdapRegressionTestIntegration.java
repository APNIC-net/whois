package net.ripe.db.whois.api.whois.rdap;

import com.google.common.base.Joiner;
import com.google.common.collect.Lists;
import net.ripe.db.whois.api.whois.rdap.domain.Autnum;
import net.ripe.db.whois.api.whois.rdap.domain.Domain;
import net.ripe.db.whois.api.whois.rdap.domain.Entity;
import net.ripe.db.whois.api.whois.rdap.domain.Ip;
import net.ripe.db.whois.common.domain.Ipv4Resource;
import net.ripe.db.whois.common.domain.Ipv6Resource;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpStatus;
import org.junit.BeforeClass;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URL;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.Scanner;

public class RdapRegressionTestIntegration {
    private static Class clazz = RdapRegressionTestIntegration.class;
    private static final Logger LOGGER = LoggerFactory.getLogger(clazz);

    // Limit the number of quries for each rdap type ( -1 no limit )
    private static final int PROCESS_MAX_QUERIES = -1;


    private static String resourcePath = "/" + clazz.getName().replace(".", "/");
    private static Properties testProperties;
    private static String rdapJsonSchema;
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

        // Load json schema
        rdapJsonSchema = new Scanner(clazz.getResourceAsStream(resourcePath + ".rdap.json")).useDelimiter("\\Z").next();

        // Test the rdap http server is reachable
        byte[] content = RdapHelperUtils.getHttpContent(rdap_server_url_base.toString(), true).body;
    }

    private static List<String> runRdapQuery(String query) throws Exception {
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

    @Test
    public void validate_all_rdap_entities_test() throws Exception {
        String type = entities.getKey();
        List<String> queries = runRdapQuery("select concat('" + rdap_server_url_base.toString() + "/" + type + "/' , pkey) from last where object_type in (" +
                Joiner.on(",").join(entities.getValue()) + ");");
        LOGGER.info(type + " query size=" + queries.size());

        int cnt = 0;
        // For each url : call each url
        for (String rdapQuery : queries) {
            try {
                RdapHelperUtils.HttpResponseElements result = RdapHelperUtils.getHttpHeaderAndContent(rdapQuery, true);
                String response = new String(result.body);
                int statusCode = result.statusCode;

                if (statusCode == HttpStatus.SC_OK) {
                    Entity entity = RdapHelperUtils.unmarshal(response, Entity.class);

                    // Manual validation checks / sanity checks

                } else {
                    net.ripe.db.whois.api.whois.rdap.domain.Error error = RdapHelperUtils.unmarshal(response, net.ripe.db.whois.api.whois.rdap.domain.Error.class);
                }

                // Validate against json schema

            } catch (Throwable ex) {
                LOGGER.error("Failed to unmarshal rdap response [" + rdapQuery + "]", ex);
            }

            if (++cnt >= PROCESS_MAX_QUERIES && PROCESS_MAX_QUERIES >= 0) {
                break;
            }
        }



    }


    @Test
    public void validate_all_rdap_domains_test() throws Exception {
        String type = domains.getKey();
        List<String> queries = runRdapQuery("select concat('" + rdap_server_url_base.toString() + "/" + type + "/' , pkey) from last where object_type in (" +
                Joiner.on(",").join(domains.getValue()) + ");");
        LOGGER.info(type + " query size=" + queries.size());

        int cnt = 0;
        // For each url : call each url
        for (String rdapQuery : queries) {
            try {
                RdapHelperUtils.HttpResponseElements result = RdapHelperUtils.getHttpHeaderAndContent(rdapQuery, true);
                String response = new String(result.body);
                int statusCode = result.statusCode;

                if (statusCode == HttpStatus.SC_OK) {
                    Domain domain = RdapHelperUtils.unmarshal(response, Domain.class);

                    // Manual validation checks / sanity checks

                } else {
                    net.ripe.db.whois.api.whois.rdap.domain.Error error = RdapHelperUtils.unmarshal(response, net.ripe.db.whois.api.whois.rdap.domain.Error.class);
                }

                // Validate against json schema

            } catch (Throwable ex) {
                LOGGER.error("Failed to unmarshal rdap response [" + rdapQuery + "]", ex);
            }

            if (++cnt >= PROCESS_MAX_QUERIES && PROCESS_MAX_QUERIES >= 0) {
                break;
            }
        }



    }

    @Test
    public void validate_all_rdap_autnums_test() throws Exception {
        String type = autnums.getKey();
        List<String> queries = runRdapQuery("select concat('" + rdap_server_url_base.toString() + "/" + type + "/' , trim(substring(pkey, 3, 50)) ) from last where object_type in (" +
                Joiner.on(",").join(autnums.getValue()) + ") and pkey like 'AS%';");
        LOGGER.info(type + " query size=" + queries.size());

        int cnt = 0;
        // For each url : call each url
        for (String rdapQuery : queries) {
            try {
                RdapHelperUtils.HttpResponseElements result = RdapHelperUtils.getHttpHeaderAndContent(rdapQuery, true);
                String response = new String(result.body);
                int statusCode = result.statusCode;

                if (statusCode == HttpStatus.SC_OK) {
                    Autnum autnum = RdapHelperUtils.unmarshal(response, Autnum.class);

                    // Manual validation checks / sanity checks

                } else {
                    net.ripe.db.whois.api.whois.rdap.domain.Error error = RdapHelperUtils.unmarshal(response, net.ripe.db.whois.api.whois.rdap.domain.Error.class);
                }

                // Validate against json schema


            } catch (Throwable ex) {
                LOGGER.error("Failed to unmarshal rdap response [" + rdapQuery + "]", ex);
            }

            if (++cnt >= PROCESS_MAX_QUERIES && PROCESS_MAX_QUERIES >= 0) {
                break;
            }
        }
    }

    @Test
    public void validate_all_rdap_ips_test() throws Exception {
        String type = ips.getKey();
        List<String> queries = runRdapQuery("select pkey from last where object_type in (" + Joiner.on(",").join(ips.getValue()) + ");");
        LOGGER.info(type + " query size=" + queries.size());

        String prefix = rdap_server_url_base.toString() + "/" + type + "/";

        int cnt = 0;
        // For each url : call each url
        for (String pkey : queries) {
            // ip query result needs to be converted
            String postfix = pkey.indexOf(":") > 0 ? Ipv6Resource.parse(pkey).toString() : Ipv4Resource.parse(pkey).toString();
            if (postfix.indexOf("-") >= 0) {
                LOGGER.warn("Cannot query ip range:" + postfix);
                continue;
            }
            String rdapQuery = prefix + postfix;
            try {
                RdapHelperUtils.HttpResponseElements result = RdapHelperUtils.getHttpHeaderAndContent(rdapQuery, true);
                String response = new String(result.body);
                int statusCode = result.statusCode;

                if (statusCode == HttpStatus.SC_OK) {
                    Ip ip = RdapHelperUtils.unmarshal(response, Ip.class);

                    // Manual validation checks / sanity checks

                } else {
                    net.ripe.db.whois.api.whois.rdap.domain.Error error = RdapHelperUtils.unmarshal(response, net.ripe.db.whois.api.whois.rdap.domain.Error.class);
                }

                // Validate against json schema


            } catch (Throwable ex) {
                LOGGER.error("Failed to unmarshal rdap response [" + rdapQuery + "]", ex);
            }

            if (++cnt >= PROCESS_MAX_QUERIES && PROCESS_MAX_QUERIES >= 0) {
                break;
            }
        }
    }


    //@Test
    public void validate_rdap_manual_test() throws Exception {
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
        } catch (Throwable ex) {
            LOGGER.error("Failed to unmarshal rdap response [" + url + "]", ex);
        }
    }

}
