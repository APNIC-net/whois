package net.ripe.db.whois.query.pipeline;

import net.ripe.db.whois.query.domain.QueryMessages;
import net.ripe.db.whois.query.query.Query;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelDownstreamHandler;
import org.jboss.netty.channel.ChannelEvent;
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

    private boolean keepAlive;
    private boolean closed;

    private int instance = new Random().nextInt(10000-1) + 1;

    @Override
    public void messageReceived(final ChannelHandlerContext ctx, final MessageEvent e) {
        final Channel channel = e.getChannel();
        final Query query = (Query) e.getMessage();
        final String queryString = "["+ query.toString() + "]";

        LOGGER(instance, "start ConnectionStateHandler.messageReceived: keepAlive=" + keepAlive + ":closed=" + closed + ":query.hasOnlyKeepAlive()=" + query.hasOnlyKeepAlive() + ":" + queryString);
        if (closed) {
            LOGGER(instance, "end ConnectionStateHandler.messageReceived: closed " + ":query.hasOnlyKeepAlive()=" + query.hasOnlyKeepAlive() + ":" + queryString);
            return;
        }

        // Case: First query has only -k, just keep connection open
        if (!keepAlive && query.hasOnlyKeepAlive()) {
            keepAlive = true;
            channel.getPipeline().sendDownstream(new QueryCompletedEvent(channel));
            return;
        }

        // Case: Last query has only -k, finish up
        if (query.hasOnlyKeepAlive()) {
            keepAlive = false;
            channel.getPipeline().sendDownstream(new QueryCompletedEvent(channel));
            return;
        }

        // Case: Any subsequent queries have -k
        if (query.hasKeepAlive()) {
            keepAlive = true;
        }

        ctx.sendUpstream(e);
        LOGGER(instance, "end ConnectionStateHandler.messageReceived: ctx.sendUpstream(e): keepAlive=" + keepAlive + ":closed=" + closed + ":" + ":query.hasOnlyKeepAlive()=" + query.hasOnlyKeepAlive() + ":" + queryString);

// Previous logic:
//        if (keepAlive && query.hasOnlyKeepAlive()) {
//            channel.close();
//            return;
//        }
//
//        if (query.hasKeepAlive()) {
//            keepAlive = true;
//        }
//
//        if (query.hasOnlyKeepAlive()) {
//            channel.getPipeline().sendDownstream(new QueryCompletedEvent(channel));
//        } else {
//            ctx.sendUpstream(e);
//        }

    }

    @Override
    public void handleDownstream(final ChannelHandlerContext ctx, final ChannelEvent e) {
        LOGGER(instance, "start ConnectionStateHandler.handleDownstream: ctx.sendDownstream(e): keepAlive=" + keepAlive + ": closed=" + closed);
        ctx.sendDownstream(e);

        if (e instanceof QueryCompletedEvent) {
            final Channel channel = e.getChannel();
            if (keepAlive) {
                channel.write(NEWLINE);
                channel.write(QueryMessages.termsAndConditions());
                LOGGER(instance,"end ConnectionStateHandler.handleDownstream:  channel.write(QueryMessages.termsAndConditions()): keepAlive=" + keepAlive + ":closed=" + closed);
            } else {
                channel.write(NEWLINE).addListener(ChannelFutureListener.CLOSE);
                LOGGER(instance, "end ConnectionStateHandler.handleDownstream:channel.write(NEWLINE).addListener(ChannelFutureListener.CLOSE): keepAlive=" + keepAlive + ":closed=" + closed);
                closed = true;
            }
        }
    }

    public static void LOGGER(int instance, String log) {
        LOGGER.info("!" + instance + "!" + log);
    }
}
