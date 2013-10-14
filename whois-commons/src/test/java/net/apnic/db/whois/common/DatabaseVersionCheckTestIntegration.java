/************************************************************************************************
 * Copyright (c) 2013, Asia Pacific Network Information Center (APNIC). All rights reserved.
 *
 * This is unpublished proprietary source code of Asia Pacific Network Information Center (APNIC)
 * The copyright notice above does not evidence any actual or intended
 * publication of such source code.
 ************************************************************************************************/
package net.apnic.db.whois.common;

import net.ripe.db.whois.common.Slf4JLogConfiguration;
import net.ripe.db.whois.common.dao.jdbc.DatabaseHelper;
import net.ripe.db.whois.common.profiles.WhoisProfile;
import org.junit.After;
import org.junit.Test;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Tests database versions against bundled sql patch files.
 * <p/>
 *
 * @author dragan@apnic.net
 *         Date: 14/10/13
 *         Time: 4:47 PM
 */
public class DatabaseVersionCheckTestIntegration implements IntegrationTest {
    protected static DatabaseHelper databaseHelper;
    private static ClassPathXmlApplicationContext applicationContext;

    @Test
    public void databaseVersionCheckSuccess() throws Exception {
        DatabaseHelper.setupDatabase();
        Slf4JLogConfiguration.init();
        WhoisProfile.setDeployed();
        applicationContext = new ClassPathXmlApplicationContext("applicationContext-commons-test.xml");
    }

    @Test
    public void databaseVersionCheckFail() throws Exception {
        DatabaseHelper.setupDatabase();

        // Change the db version
        JdbcTemplate jdbcTemplate = DatabaseHelper.createJdbcTemplate("WHOIS");
        jdbcTemplate.execute("UPDATE version SET version = 'whois-0.9' WHERE version like 'whois-%'");

        Slf4JLogConfiguration.init();
        WhoisProfile.setDeployed();

        try {
            applicationContext = new ClassPathXmlApplicationContext("applicationContext-commons-test.xml");
            applicationContext.refresh();
        } catch (Throwable t) {
            org.junit.Assert.assertTrue(t instanceof RuntimeException);
        }
        org.junit.Assert.assertNull(applicationContext);
    }

    @After
    public void tearDown() throws Exception {
        WhoisProfile.reset();
        if (applicationContext != null) {
            DatabaseHelper databaseHelper = (DatabaseHelper)applicationContext.getBean("databaseHelper");
            databaseHelper.setup();
            applicationContext.registerShutdownHook();
            applicationContext.destroy();
        }
        applicationContext = null;
    }

}
