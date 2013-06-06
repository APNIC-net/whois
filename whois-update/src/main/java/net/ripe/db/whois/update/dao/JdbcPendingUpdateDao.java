package net.ripe.db.whois.update.dao;

import net.ripe.db.whois.common.dao.jdbc.domain.ObjectTypeIds;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.rpsl.RpslObjectBase;
import net.ripe.db.whois.update.domain.PendingUpdate;
import org.joda.time.LocalDateTime;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Repository;

import javax.sql.DataSource;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.List;

@Repository
public class JdbcPendingUpdateDao implements PendingUpdateDao {
    private final JdbcTemplate jdbcTemplate;

    @Autowired
    public JdbcPendingUpdateDao(@Qualifier("pendingDataSource") final DataSource dataSource) {
        this.jdbcTemplate = new JdbcTemplate(dataSource);
    }

    @Override
    public List<PendingUpdate> findByTypeAndKey(final ObjectType type, final String key) {
        return jdbcTemplate.query("SELECT * FROM pending_updates WHERE object_type = ? AND pkey = ? ORDER BY stored_date ASC",
                new Object[]{ObjectTypeIds.getId(type), key},
                new RowMapper<PendingUpdate>() {
            @Override
            public PendingUpdate mapRow(final ResultSet rs, final int rowNum) throws SQLException {
                return new PendingUpdate(
                        rs.getString("authenticated_by"),
                        RpslObjectBase.parse(rs.getBytes("object")),
                        new LocalDateTime(rs.getInt("stored_date") * 1000L)
                );
            }
        });
    }

    @Override
    public void store(final PendingUpdate pendingUpdate) {
        jdbcTemplate.update("" +
                "INSERT INTO pending_updates(object, object_type, pkey, stored_date, authenticated_by) " +
                "VALUES (?, ?, ?, ?, ?)",
                pendingUpdate.getObject().toByteArray(),
                ObjectTypeIds.getId(pendingUpdate.getObject().getType()),
                pendingUpdate.getObject().getKey(),
                (int) pendingUpdate.getStoredDate().toDate().getTime() / 1000L,
                pendingUpdate.getAuthenticatedBy());
    }

    @Override
    public void remove(final PendingUpdate pendingUpdate) {
        jdbcTemplate.update("DELETE FROM pending_updates WHERE object_type = ? AND pkey = ? ORDER BY stored_date ASC LIMIT 1",
                ObjectTypeIds.getId(pendingUpdate.getObject().getType()),
                pendingUpdate.getObject().getKey().toString());
    }
}
