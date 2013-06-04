package net.apnic.db.whois.update;

import net.apnic.db.whois.common.IntegrationTest;
import net.apnic.db.whois.update.handler.validator.domain.DsRdataAuthorisationValidator;
import net.ripe.db.whois.common.profiles.WhoisVariant;
import net.ripe.db.whois.update.dao.AbstractDaoTest;
import net.ripe.db.whois.update.handler.validator.poem.PoemHasOnlyPublicMaintainerValidator;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.rules.ExpectedException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.util.StringUtils;

import javax.sql.DataSource;

import static org.junit.Assert.assertNotNull;

@Category(IntegrationTest.class)
public class UpdateTestIntegration extends AbstractDaoTest {
    private static final Logger LOGGER = LoggerFactory.getLogger(UpdateTestIntegration.class);

    @Rule public ExpectedException exception = ExpectedException.none();

    @Autowired @Qualifier("sourceAwareDataSource") DataSource dataSource;

    @BeforeClass
    public static void beforeClass() throws Exception {
        WhoisVariant.setWhoIsVariant(WhoisVariant.Type.APNIC);
        LOGGER.info("Setting whois variant [" + WhoisVariant.getWhoIsVariant() + "]");
    }

    @Test
    public void see_if_server_starts_and_expected_bean_present_test() throws Exception {
        DsRdataAuthorisationValidator dsRdataAuthorisationValidator = (DsRdataAuthorisationValidator)applicationContext.getBean(StringUtils.uncapitalize(DsRdataAuthorisationValidator.class.getSimpleName()));
        assertNotNull(dsRdataAuthorisationValidator);
        exception.expect(NoSuchBeanDefinitionException.class);
        applicationContext.getBean(StringUtils.uncapitalize(PoemHasOnlyPublicMaintainerValidator.class.getSimpleName()));
    }

    @AfterClass
    public static void afterClass() {
        WhoisVariant.setWhoIsVariant(WhoisVariant.Type.NONE);
        LOGGER.info("Unsetting whois variant [" + WhoisVariant.getWhoIsVariant() + "]");
    }
}
