package net.ripe.db.whois.common.source;

import com.google.common.base.Function;
import com.google.common.base.Splitter;
import com.google.common.collect.Iterables;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import com.mchange.v2.c3p0.DataSources;
import net.ripe.db.whois.common.domain.CIString;
import net.ripe.db.whois.common.jdbc.DataSourceFactory;
import net.ripe.db.whois.common.jdbc.DatabaseVersionCheck;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Component;

import javax.annotation.CheckForNull;
import javax.annotation.Nullable;
import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import javax.sql.DataSource;
import java.sql.SQLException;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

import static net.ripe.db.whois.common.domain.CIString.ciSet;
import static net.ripe.db.whois.common.domain.CIString.ciString;

@Component
public class SourceContext {
    private static final Logger LOGGER = LoggerFactory.getLogger(SourceContext.class);
    private static final Splitter COMMA_SPLITTER = Splitter.on(',').omitEmptyStrings();

    private final Source mainMasterSource;
    private final Source mainSlaveSource;

    private final Map<Source, SourceConfiguration> sourceConfigurations = Maps.newLinkedHashMap();

    private final Set<CIString> grsSourceNames;
    private final Set<CIString> grsSourceNamesForDummification;
    private final Set<CIString> mirrorSourceNames;
    private final Set<CIString> allSourceNames;
    private final Set<CIString> additionalSourceNames;
    private final Map<CIString, CIString> aliases;
    private DatabaseVersionCheck databaseVersionCheck;

    private ThreadLocal<SourceConfiguration> current = new ThreadLocal<>();
    private final ApplicationContext applicationContext;

    @Autowired
    public SourceContext(
            @Value("${whois.source}") final String mainSourceNameString,
            @Value("${whois.additional.sources}") final String additionalSourceNames,
            @Value("${grs.sources}") final String grsSourceNames,
            @Value("${nrtm.import.sources}") final String nrtmSourceNames,
            @Value("${mirror.sources}") final String mirrorSourceNames,
            @Value("${grs.sources.dummify}") final String grsSourceNamesForDummification,
            @Value("${whois.db.grs.master.baseurl}") final String grsMasterBaseUrl,
            @Value("${whois.db.master.username}") final String whoisMasterUsername,
            @Value("${whois.db.master.password}") final String whoisMasterPassword,
            @Value("${whois.db.grs.slave.baseurl}") final String grsSlaveBaseUrl,
            @Value("${whois.db.mirror.slave.baseurl}") final String mirrorSlaveBaseUrl,
            @Value("${whois.db.slave.username}") final String whoisSlaveUsername,
            @Value("${whois.db.slave.password}") final String whoisSlavePassword,
            @Qualifier("whoisMasterDataSource") final DataSource whoisMasterDataSource,
            @Qualifier("whoisSlaveDataSource") final DataSource whoisSlaveDataSource,
            final DataSourceFactory dataSourceFactory,
            final ApplicationContext applicationContext) {

        this.applicationContext = applicationContext;
        final CIString mainSourceName = ciString(mainSourceNameString);
        this.mainMasterSource = Source.master(mainSourceName);
        this.mainSlaveSource = Source.slave(mainSourceName);

        final Set<CIString> additionalSources = Sets.newLinkedHashSet();
        final Set<CIString> grsSources = Sets.newLinkedHashSet();
        final Set<CIString> mirrorSources = Sets.newLinkedHashSet();
        final Map<CIString, CIString> aliases = Maps.newLinkedHashMap();

        sourceConfigurations.put(mainMasterSource, new SourceConfiguration(mainMasterSource, whoisMasterDataSource));
        sourceConfigurations.put(mainSlaveSource, new SourceConfiguration(mainSlaveSource, whoisSlaveDataSource));

        final Iterable<CIString> grsSourceNameIterable = Iterables.transform(COMMA_SPLITTER.split(grsSourceNames), new Function<String, CIString>() {
            @Nullable
            @Override
            public CIString apply(final String input) {
                return ciString(input);
            }
        });

        final Iterable<CIString> mirrorSourceNameIterable = Iterables.transform(COMMA_SPLITTER.split(mirrorSourceNames), new Function<String, CIString>() {
            @Nullable
            @Override
            public CIString apply(final String input) {
                return ciString(input);
            }
        });


        final Iterable<CIString> nrtmSourceNameIterable = Iterables.transform(COMMA_SPLITTER.split(nrtmSourceNames), new Function<String, CIString>() {
            @Nullable
            @Override
            public CIString apply(final String input) {
                return ciString(input);
            }
        });

        for (final CIString grsSourceName : Iterables.concat(grsSourceNameIterable, nrtmSourceNameIterable)) {
            if (!grsSourceName.endsWith(ciString("-GRS"))) {
                LOGGER.warn("Invalid GRS source name: {}", grsSourceName);
                continue;
            }

            if (!grsSources.add(grsSourceName)) {
                LOGGER.warn("GRS Source already configured: {}", grsSourceName);
                continue;
            }

            final Source grsMasterSource = Source.master(grsSourceName);
            final Source grsSlaveSource = Source.slave(grsSourceName);

            if (grsSourceName.contains(mainSourceName)) {
                LOGGER.info("Delegating source {} to {}", grsSourceName, mainSourceName);
                aliases.put(grsSourceName, mainSlaveSource.getName());
                sourceConfigurations.put(grsMasterSource, new SourceConfiguration(grsMasterSource, whoisMasterDataSource));
                sourceConfigurations.put(grsSlaveSource, new SourceConfiguration(grsSlaveSource, whoisSlaveDataSource));
            } else {
                final String grsSlaveUrl = createSourceUrl(grsSlaveBaseUrl, grsSourceName);
                final DataSource grsSlaveDataSource = dataSourceFactory.createDataSource(grsSlaveUrl, whoisSlaveUsername, whoisSlavePassword);
                sourceConfigurations.put(grsSlaveSource, new SourceConfiguration(grsSlaveSource, grsSlaveDataSource));

                final String grsMasterUrl = createSourceUrl(grsMasterBaseUrl, grsSourceName);
                final DataSource grsMasterDataSource = dataSourceFactory.createDataSource(grsMasterUrl, whoisMasterUsername, whoisMasterPassword);
                sourceConfigurations.put(grsMasterSource, new SourceConfiguration(grsMasterSource, grsMasterDataSource));
            }
        }

        for (final CIString mirrorSourceName : mirrorSourceNameIterable) {
            if (!mirrorSources.add(mirrorSourceName)) {
                LOGGER.warn("Mirror Source already configured: {}", mirrorSourceName);
                continue;
            }

            final Source mirrorSlaveSource = Source.slave(mirrorSourceName);

            final String mirrorSlaveUrl = createSourceUrl(mirrorSlaveBaseUrl, mirrorSourceName);
            final DataSource mirrorSlaveDataSource = dataSourceFactory.createDataSource(mirrorSlaveUrl, whoisSlaveUsername, whoisSlavePassword);
            sourceConfigurations.put(mirrorSlaveSource, new SourceConfiguration(mirrorSlaveSource, mirrorSlaveDataSource));
        }

        LOGGER.info("Using sources: {}", sourceConfigurations.keySet());

        this.grsSourceNames = Collections.unmodifiableSet(grsSources);
        this.grsSourceNamesForDummification = ciSet(COMMA_SPLITTER.split(grsSourceNamesForDummification));
        this.mirrorSourceNames = Collections.unmodifiableSet(mirrorSources);
        this.aliases = Collections.unmodifiableMap(aliases);
        this.allSourceNames = Collections.unmodifiableSet(Sets.newLinkedHashSet(Iterables.transform(sourceConfigurations.keySet(), new Function<Source, CIString>() {
            @Nullable
            @Override
            public CIString apply(final Source source) {
                return source.getName();
            }
        })));

        for (final CIString sourceName : CIString.ciSet(COMMA_SPLITTER.split(additionalSourceNames))) {
            if (this.allSourceNames.contains(sourceName)) {
                additionalSources.add(sourceName);
            }
            else {
                LOGGER.error("Additional source {} not found in configured sources", sourceName);
                throw new IllegalSourceException(sourceName.toString());
            }
        }

        this.additionalSourceNames = Collections.unmodifiableSet(additionalSources);

        if (!additionalSources.isEmpty()) {
            LOGGER.info("Additional sources: {}", additionalSources);
        }
        if (databaseVersionCheck != null) {
            databaseVersionCheck.check(applicationContext);
        }
    }

    @Autowired(required = false)
    public void setDatabaseVersionCheck(DatabaseVersionCheck databaseVersionCheck) {
        this.databaseVersionCheck = databaseVersionCheck;
    }

    @PostConstruct
    public void init() {
        if (databaseVersionCheck != null) {
            databaseVersionCheck.check(applicationContext);
        }
    }

    private String createSourceUrl(final String baseUrl, final CIString sourceName) {
        return String.format("%s_%s", baseUrl, sourceName.toString().replace('-', '_'));
    }

    public SourceConfiguration getCurrentSourceConfiguration() {
        final SourceConfiguration sourceConfiguration = current.get();
        if (sourceConfiguration == null) {
            return sourceConfigurations.get(mainMasterSource);
        }

        return sourceConfiguration;
    }

    public Collection<SourceConfiguration> getAllSourceConfigurations() {
        return sourceConfigurations.values();
    }

    public SourceConfiguration getSourceConfiguration(final Source source) {
        final SourceConfiguration sourceConfiguration = sourceConfigurations.get(source);
        if (sourceConfiguration == null) {
            throw new IllegalSourceException(source.toString());
        }

        return sourceConfiguration;
    }

    @PreDestroy
    public void destroyDataSources() {
        for (final SourceConfiguration sourceConfig : sourceConfigurations.values()) {
            try {
                DataSources.destroy(sourceConfig.getDataSource());
            } catch (SQLException e) {
                LOGGER.error("Destroying datasource", e);
            }
        }
    }

    public Set<CIString> getAllSourceNames() {
        return allSourceNames;
    }

    public Set<CIString> getGrsSourceNames() {
        return grsSourceNames;
    }

    public Set<CIString> getMirrorSourceNames() {
        return mirrorSourceNames;
    }

    public Set<CIString> getAdditionalSourceNames() {
        return additionalSourceNames;
    }

    @CheckForNull
    public CIString getAlias(final CIString source) {
        return aliases.get(source);
    }

    public void setCurrentSourceToWhoisMaster() {
        setCurrent(mainMasterSource);
    }

    public void setCurrent(final Source source) {
        final SourceConfiguration sourceConfiguration = sourceConfigurations.get(source);
        if (sourceConfiguration == null) {
            throw new IllegalSourceException(source.getName().toString());
        }

        current.set(sourceConfiguration);
    }

    public Source getWhoisSlaveSource() {
        return mainSlaveSource;
    }

    public Source getCurrentSource() {
        return getCurrentSourceConfiguration().getSource();
    }

    public void removeCurrentSource() {
        current.remove();
    }

    public boolean isAcl() {
        return !grsSourceNames.contains(getCurrentSource().getName());
    }

    public boolean isVirtual() {
        return isVirtual(getCurrentSource().getName());
    }

    public boolean isVirtual(final CIString source) {
        return aliases.containsKey(source);
    }

    public boolean isDummificationRequired() {
        final CIString sourceName = getCurrentSource().getName();
        return grsSourceNamesForDummification.contains(sourceName);
    }

}
