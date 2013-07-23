package net.apnic.db.whois.query.query;

import net.ripe.db.whois.query.query.Query;
import org.junit.Test;

import static org.junit.Assert.assertFalse;

public class QueryTest {
    private Query subject;

    private Query parseWithNewline(String input) {
        // [EB]: userinput will always be newline terminated
        return Query.parse(input + "\n");
    }

    private void parse(String input) {
        subject = parseWithNewline(input);
    }

    @Test
    public void default_is_non_filtered() {
        parse("foo");

        assertFalse(subject.isFiltered());
    }
}
