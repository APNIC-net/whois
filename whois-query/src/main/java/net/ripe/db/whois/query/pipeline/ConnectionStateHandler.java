package net.ripe.db.whois.query.pipeline;

import net.ripe.db.whois.query.domain.QueryMessages;
import net.ripe.db.whois.query.query.Query;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelDownstreamHandler;
import org.jboss.netty.channel.ChannelEvent;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.ChannelFutureListener;
import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.channel.SimpleChannelUpstreamHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ConnectionStateHandler extends SimpleChannelUpstreamHandler implements ChannelDownstreamHandler {
    private static final Logger LOGGER = LoggerFactory.getLogger(ConnectionStateHandler.class);

    static final ChannelBuffer NEWLINE = ChannelBuffers.wrappedBuffer(new byte[]{'\n'});

    private boolean keepAlive = false;
    private boolean closed = false;
    private int closedQueryCount = 0;
    private boolean firstQuery = true;

    @Override
    public void messageReceived(final ChannelHandlerContext ctx, final MessageEvent e) {
        final Channel channel = e.getChannel();
        final Query query = (Query) e.getMessage();

        if (closed) {
            // If we get more than 5 queries while in closed state, force close the connection
            if (++closedQueryCount > 5) {
                channel.close();
            }
            return;
        }

        boolean localFirstQuery = firstQuery;
        firstQuery = false;

        if (localFirstQuery && query.hasKeepAlive()) {
            // Case: First query contains -k, keep the connection open
            keepAlive = true;
            channel.getPipeline().sendDownstream(new QueryCompletedEvent(channel));

            // Case: First query is a single -k, keep the connection open, and just return
            if (query.hasOnlyKeepAlive()) {
                return;
            }
        }

        // Case: Last query is a single -k, return and cleanup normally
        if (!localFirstQuery && query.hasOnlyKeepAlive()) {
            keepAlive = false;
            channel.getPipeline().sendDownstream(new QueryCompletedEvent(channel));
            return;
        }

        ctx.sendUpstream(e);
    }

    @Override
    public void handleDownstream(final ChannelHandlerContext ctx, final ChannelEvent e) {
        ctx.sendDownstream(e);

        if (e instanceof QueryCompletedEvent) {
            final Channel channel = e.getChannel();
            ChannelFuture cf = channel.write(NEWLINE);
            if (keepAlive) {
                channel.write(QueryMessages.termsAndConditions());
            } else {
                cf.addListener(ChannelFutureListener.CLOSE);
                closed = true;
            }
        }
    }
}
