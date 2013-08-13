package net.ripe.db.whois.query.pipeline;

import net.ripe.db.whois.common.domain.ResponseObject;
import net.ripe.db.whois.common.pipeline.ChannelUtil;
import net.ripe.db.whois.query.domain.QueryCompletionInfo;
import net.ripe.db.whois.query.domain.QueryException;
import net.ripe.db.whois.query.domain.ResponseHandler;
import net.ripe.db.whois.query.handler.QueryHandler;
import net.ripe.db.whois.query.query.Query;
import org.jboss.netty.channel.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Random;

public class WhoisServerHandler extends SimpleChannelUpstreamHandler {
    private static final Logger LOGGER = LoggerFactory.getLogger(ConnectionStateHandler.class);

    private final QueryHandler queryHandler;
    private boolean closed;
    private int instance = new Random().nextInt(10000-1) + 1;

    public WhoisServerHandler(final QueryHandler queryHandler) {
        this.queryHandler = queryHandler;
    }

    @Override
    public void messageReceived(final ChannelHandlerContext ctx, final MessageEvent event) {
        final Query query = (Query) event.getMessage();
        final String queryString = "["+ query.toString() + "]";
        LOGGER(instance, "start WhoisServerHandler.messageReceived: closed=" + closed + ": " + queryString);
        final Channel channel = event.getChannel();
        queryHandler.streamResults(query, ChannelUtil.getRemoteAddress(channel), channel.getId(), new ResponseHandler() {
            @Override
            public String getApi() {
                return "QRY";
            }

            @Override
            public void handle(final ResponseObject responseObject) {
                if (closed) { // Prevent hammering a closed channel
                    LOGGER(instance, "return WhoisServerHandler.messageReceived : THROW NEW QUERYEXCEPTION(QueryCompletionInfo.DISCONNECTED): closed=" + closed + ": " + queryString);
                    throw new QueryException(QueryCompletionInfo.DISCONNECTED);
                }

                LOGGER(instance, "WhoisServerHandler.messageReceived : channel.write(responseObject).isDone(): closed=" + closed + ": " + queryString);
                // Wait for the write to finish
                channel.write(responseObject).awaitUninterruptibly();

            }
        });

        LOGGER(instance, "end WhoisServerHandler.messageReceived : channel.getPipeline().sendDownstream: closed=" + closed + ": " + queryString);
        channel.getPipeline().sendDownstream(new QueryCompletedEvent(channel));
    }

    @SuppressWarnings("PMD.SignatureDeclareThrowsException") // Base class throws exception
    @Override
    public void channelClosed(final ChannelHandlerContext ctx, final ChannelStateEvent e) throws Exception {
        closed = true;
        super.channelClosed(ctx, e);
        LOGGER(instance, "end WhoisServerHandler.channelClosed: super.channelClosed(ctx, e) : closed=" + closed + ": " + e.getClass().getName());
    }


    public static void LOGGER(int instance, String log) {
        LOGGER.info("!" + instance + "!" + log);
    }

}
