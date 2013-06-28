package net.ripe.db.whois.api.mail;

import net.ripe.db.whois.update.domain.ContentWithCredentials;
import net.ripe.db.whois.update.domain.Keyword;
import net.ripe.db.whois.update.domain.Origin;

import java.util.Iterator;
import java.util.List;

public class MailMessage implements Origin {
    private final String id;
    private final String from;
    private final String subject;
    private final String date;
    private final String replyTo;
    private final String replyToEmail;
    private final Keyword keyword;
    private final List<ContentWithCredentials> contentWithCredentials;

    public MailMessage(final String id, final String from, final String subject, final String date, final String replyTo, String replyToEmail, final Keyword keyword, List<ContentWithCredentials> contentWithCredentials) {
        this.id = id;
        this.from = from;
        this.subject = subject;
        this.date = date;
        this.replyTo = replyTo;
        this.keyword = keyword;
        this.contentWithCredentials = contentWithCredentials;
        this.replyToEmail = replyToEmail;
    }

    @Override
    public boolean isDefaultOverride() {
        return false;
    }

    @Override
    public boolean allowAdminOperations() {
        return false;
    }

    public String getId() {
        return id;
    }

    public String getSubject() {
        return subject;
    }

    public String getDate() {
        return date;
    }

    /** full from: header */
    public String getReplyTo() {
        return replyTo;
    }

    /** just the email address itself */
    public String getReplyToEmail() {
        return replyToEmail;
    }

    public String getUpdateMessage() {
        StringBuilder builder = new StringBuilder();

        Iterator<ContentWithCredentials> iterator = contentWithCredentials.iterator();
        while (iterator.hasNext()) {
            builder.append(iterator.next().getContent());
            if (iterator.hasNext()) {
                builder.append("\n\n");
            }
        }
        return builder.toString();
    }

    public List<ContentWithCredentials> getContentWithCredentials() {
        return contentWithCredentials;
    }

    @Override
    public String getFrom() {
        return from;
    }

    public Keyword getKeyword() {
        return keyword;
    }

    @Override
    public String getResponseHeader() {
        return String.format("" +
                ">  From:       %s\n" +
                ">  Subject:    %s\n" +
                ">  Date:       %s\n" +
                ">  Reply-To:   %s\n" +
                ">  Message-ID: %s",
                from,
                subject,
                date,
                replyTo,
                id);
    }

    @Override
    public String getNotificationHeader() {
        return String.format("" +
                "- From:      %s\n" +
                "- Date/Time: %s\n",
                from,
                date);
    }

    @Override
    public String getName() {
        return getType().getName();
    }

    @Override
    public Type getType() {
        return Type.EMAIL_UPDATE;
    }

    @Override
    public String toString() {
        return "Mail(" + getId() + ")";
    }
}
