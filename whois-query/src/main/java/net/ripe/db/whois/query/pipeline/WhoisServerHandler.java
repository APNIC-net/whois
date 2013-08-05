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

public class WhoisServerHandler extends SimpleChannelUpstreamHandler {
    private static final Logger LOGGER = LoggerFactory.getLogger(ConnectionStateHandler.class);

    private final QueryHandler queryHandler;
    private boolean closed;

    public WhoisServerHandler(final QueryHandler queryHandler) {
        this.queryHandler = queryHandler;
    }

    @Override
    public void messageReceived(final ChannelHandlerContext ctx, final MessageEvent event) {
        final Query query = (Query) event.getMessage();
        final String queryString = "["+ query.toString() + "]";
        LOGGER.info("!start WhoisServerHandler.messageReceived: " + queryString);
        final Channel channel = event.getChannel();
        queryHandler.streamResults(query, ChannelUtil.getRemoteAddress(channel), channel.getId(), new ResponseHandler() {
            @Override
            public String getApi() {
                return "QRY";
            }

            @Override
            public void handle(final ResponseObject responseObject) {
                if (closed) { // Prevent hammering a closed channel
                    LOGGER.info("!end WhoisServerHandler.messageReceived : throw QueryException(QueryCompletionInfo.DISCONNECTED): " + queryString);
                    throw new QueryException(QueryCompletionInfo.DISCONNECTED);
                }

                LOGGER.info("!end WhoisServerHandler.messageReceived : channel.write(responseObject): " + queryString);
                channel.write(responseObject);
            }
        });

        channel.getPipeline().sendDownstream(new QueryCompletedEvent(channel));
    }

    @SuppressWarnings("PMD.SignatureDeclareThrowsException") // Base class throws exception
    @Override
    public void channelClosed(final ChannelHandlerContext ctx, final ChannelStateEvent e) throws Exception {
        LOGGER.info("!start WhoisServerHandler.channelClosed");
        closed = true;
        super.channelClosed(ctx, e);
    }
}
