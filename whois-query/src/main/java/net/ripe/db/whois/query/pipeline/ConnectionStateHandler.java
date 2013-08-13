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

import java.util.Random;

public class ConnectionStateHandler extends SimpleChannelUpstreamHandler implements ChannelDownstreamHandler {
    private static final Logger LOGGER = LoggerFactory.getLogger(ConnectionStateHandler.class);

    static final ChannelBuffer NEWLINE = ChannelBuffers.wrappedBuffer(new byte[]{'\n'});

    private boolean keepAlive = false;
    private boolean closed = false;
    private boolean firstQuery = true;

    private int instance = new Random().nextInt(10000 - 1) + 1;

    @Override
    public void messageReceived(final ChannelHandlerContext ctx, final MessageEvent e) {
        final Channel channel = e.getChannel();
        final Query query = (Query) e.getMessage();
        final String queryString = "[" + query.toString() + "]";

        LOGGER(instance, "start ConnectionStateHandler.messageReceived: :closed=" + closed + ":query.hasOnlyKeepAlive()=" + query.hasOnlyKeepAlive() + ":" + queryString);
        if (closed) {
            // Now call close since all queries hae been processed.
            // Note: Calling this method on a closed channel has no effect.
            channel.close();
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
        //LOGGER(instance, "start ConnectionStateHandler.handleDownstream: ctx.sendDownstream(e): keepAlive=" + keepAlive + ": closed=" + closed);
        ctx.sendDownstream(e);

        if (e instanceof QueryCompletedEvent) {
            final Channel channel = e.getChannel();
            ChannelFuture cf = channel.write(NEWLINE);
            if (keepAlive) {
                channel.write(QueryMessages.termsAndConditions());
                //LOGGER(instance,"end ConnectionStateHandler.handleDownstream:  channel.write(QueryMessages.termsAndConditions()): keepAlive=" + keepAlive + ":closed=" + closed);
            } else {
                cf.addListener(ChannelFutureListener.CLOSE);
                //LOGGER(instance, "end ConnectionStateHandler.handleDownstream:channel.write(NEWLINE).addListener(ChannelFutureListener.CLOSE): keepAlive=" + keepAlive + ":closed=" + closed);
                closed = true;
            }
        }
    }

    public static void LOGGER(int instance, String log) {
        LOGGER.info("!" + instance + "!" + log);
    }
}
