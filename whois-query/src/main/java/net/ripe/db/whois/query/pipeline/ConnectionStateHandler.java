package net.ripe.db.whois.query.pipeline;

import net.ripe.db.whois.query.domain.QueryMessages;
import net.ripe.db.whois.query.query.Query;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.channel.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ConnectionStateHandler extends SimpleChannelUpstreamHandler implements ChannelDownstreamHandler {
    private static final Logger LOGGER = LoggerFactory.getLogger(ConnectionStateHandler.class);

    static final ChannelBuffer NEWLINE = ChannelBuffers.wrappedBuffer(new byte[]{'\n'});

    private boolean keepAlive;
    private boolean closed;

    @Override
    public void messageReceived(final ChannelHandlerContext ctx, final MessageEvent e) {
        final Query query = (Query) e.getMessage();
        String queryString = "["+ query.toString() + "]";
        LOGGER.info("!start ConnectionStateHandler.messageReceived: " + queryString);
        if (closed) {
            LOGGER.info("!end ConnectionStateHandler.messageReceived: closed " + queryString);
            return;
        }

        final Channel channel = e.getChannel();


        if (keepAlive && query.hasOnlyKeepAlive()) {
            channel.close();
            LOGGER.info("!end ConnectionStateHandler.messageReceived: channel.close() " + queryString);
            return;
        }

        if (query.hasKeepAlive()) {
            keepAlive = true;
        }

        if (query.hasOnlyKeepAlive()) {
            LOGGER.info("!end ConnectionStateHandler.messageReceived: channel.getPipeline().sendDownstream(new QueryCompletedEvent(channel)) " +queryString);
            channel.getPipeline().sendDownstream(new QueryCompletedEvent(channel));
        } else {
            LOGGER.info("!end ConnectionStateHandler.messageReceived: ctx.sendUpstream(e) " + queryString);
            ctx.sendUpstream(e);
        }

    }

    @Override
    public void handleDownstream(final ChannelHandlerContext ctx, final ChannelEvent e) {
        ctx.sendDownstream(e);

        if (e instanceof QueryCompletedEvent) {
            final Channel channel = e.getChannel();
            if (keepAlive && !((QueryCompletedEvent) e).isForceClose()) {
                channel.write(NEWLINE);
                channel.write(QueryMessages.termsAndConditions());
            } else {
                closed = true;
                channel.write(NEWLINE).addListener(ChannelFutureListener.CLOSE);
            }
        }
    }
}
