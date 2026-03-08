package com.kyvislabs.ntfy.client;

import com.inductiveautomation.ignition.client.gateway_interface.GatewayConnection;
import com.kyvislabs.ntfy.common.scripting.AbstractScriptModule;
import com.kyvislabs.ntfy.common.scripting.NtfyClientScripts;

public class ClientScriptModule extends AbstractScriptModule {

    private static final NtfyClientScripts RPC = GatewayConnection.getRpcInterface(
            NtfyClientScripts.SERIALIZER,
            "com.kyvislabs.ntfy",
            NtfyClientScripts.class
    );

    @Override
    protected boolean sendMessageImpl(String serverUrl, String topic, String message, String title,
            String tags, String priority, String clickAction, String attach, String actions, String icon,
            String username, String password) {
        return RPC.sendMessage(serverUrl, topic, message, title, tags, priority, clickAction, attach,
                actions, icon, username, password);
    }
}
