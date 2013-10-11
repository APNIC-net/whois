package net.ripe.db.whois.logsearch.api;

import com.google.common.base.Charsets;
import net.ripe.db.whois.common.domain.Hosts;
import net.ripe.db.whois.logsearch.LogFileSearch;
import net.ripe.db.whois.logsearch.logformat.LoggedUpdate;
import org.apache.commons.lang.StringUtils;
import org.apache.lucene.queryparser.classic.ParseException;
import org.joda.time.LocalDate;
import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.ws.rs.DefaultValue;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.StreamingOutput;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.util.Set;

/**
 * Search log files.
 */
@Component
@Path("/logs")
public class LogSearchService {
    private static final Logger LOGGER = LoggerFactory.getLogger(LogSearchService.class);

    private static final DateTimeFormatter DATE_FORMAT = DateTimeFormat.forPattern("yyyyMMdd");

    private final Hosts host = Hosts.getLocalHost();
    private final LogFileSearch logFileSearch;

    @Autowired
    public LogSearchService(final LogFileSearch logFileSearch) {
        this.logFileSearch = logFileSearch;
    }

    @GET
    @Produces(MediaType.TEXT_PLAIN)
    public Response getUpdates(
            @QueryParam("search") final String search,
            @DefaultValue("") @QueryParam("todate") final String toDate,
            @DefaultValue("") @QueryParam("fromdate") final String fromDate) throws IOException {

        final Set<LoggedUpdate> updateIds = getUpdateIds(search, toDate, fromDate);
        return Response.ok(new StreamingOutput() {
            @Override
            public void write(OutputStream output) throws IOException, WebApplicationException {
                try {
                    final Writer writer = new BufferedWriter(new OutputStreamWriter(output, Charsets.UTF_8));
                    writer.write(String.format("*** Found %s update log(s)", updateIds.size()));
                    writer.flush();

                    int count = 1;
                    for (final LoggedUpdate update : updateIds) {
                        writer.write(String.format("\n\n*** %03d ***\n\n", count++));
                        logFileSearch.writeLoggedUpdate(update, writer);
                        writer.flush();
                    }

                } catch (IOException | RuntimeException e) {
                    LOGGER.error(e.getMessage(), e);
                    throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
                }
            }
        }).build();
    }

    private Set<LoggedUpdate> getUpdateIds(final String search, final String toDate, final String fromDate) throws IOException {
        try {
            final LocalDate localDateFrom = StringUtils.isEmpty(fromDate) ? null : DATE_FORMAT.parseLocalDate(fromDate);
            final LocalDate localDateTo = StringUtils.isEmpty(toDate) ? null : DATE_FORMAT.parseLocalDate(toDate);

            return logFileSearch.searchLoggedUpdateIds(search, localDateFrom, localDateTo);
        } catch (ParseException e) {
            throw new IllegalArgumentException(String.format("Invalid query: %s", search));
        }
    }
}
