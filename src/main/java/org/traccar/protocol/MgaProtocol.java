package org.traccar.protocol;

import io.netty.handler.codec.LengthFieldBasedFrameDecoder;
import io.netty.handler.codec.string.StringEncoder;
import org.traccar.BaseProtocol;
import org.traccar.PipelineBuilder;
import org.traccar.TrackerServer;
import org.traccar.config.Config;

import jakarta.inject.Inject;
import org.traccar.model.Command;

public class MgaProtocol extends BaseProtocol {

    @Inject
    public MgaProtocol(Config config) {
        setSupportedDataCommands(
                Command.TYPE_ENGINE_RESUME,
                Command.TYPE_ENGINE_STOP,
                Command.TYPE_SET_TIMEZONE,
                Command.TYPE_REBOOT_DEVICE);
        addServer(new TrackerServer(config, getName(), false) {
            @Override
            protected void addProtocolHandlers(PipelineBuilder pipeline, Config config) {
                // pipeline.addLast(new MgaFrameDecoder());
                pipeline.addLast(new StringEncoder());
                pipeline.addLast(new MgaProtocolEncoder(MgaProtocol.this));
                pipeline.addLast(new MgaProtocolDecoder(MgaProtocol.this));
            }
        });
    }

}
