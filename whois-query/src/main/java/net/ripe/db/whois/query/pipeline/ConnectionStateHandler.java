package net.ripe.db.whois.query.pipeline;

import net.ripe.db.whois.query.domain.QueryMessages;
import net.ripe.db.whois.query.query.Query;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.channel.*;

public class ConnectionStateHandler extends SimpleChannelUpstreamHandler implements ChannelDownstreamHandler {

    static final ChannelBuffer NEWLINE = ChannelBuffers.wrappedBuffer(new byte[]{'\n'});

    private boolean keepAlive;
    private boolean closed;

    @Override
    public void messageReceived(final ChannelHandlerContext ctx, final MessageEvent e) {
        if (closed) {
            return;
        }

        final Channel channel = e.getChannel();
        final Query query = (Query) e.getMessage();

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
    }

    @Override
    public void handleDownstream(final ChannelHandlerContext ctx, final ChannelEvent e) {
        ctx.sendDownstream(e);

        if (e instanceof QueryCompletedEvent) {
            final Channel channel = e.getChannel();
            if (keepAlive) {
                channel.write(NEWLINE);
                channel.write(QueryMessages.termsAndConditions());
            } else {
                closed = true;
                channel.write(NEWLINE).addListener(ChannelFutureListener.CLOSE);
            }
        }
    }
}
