package com.kyvislabs.ntfy.client;

import com.inductiveautomation.ignition.client.gateway_interface.ModuleRPCFactory;
import com.inductiveautomation.ignition.common.script.hints.NoHint;
import com.kyvislabs.ntfy.common.scripting.AbstractScriptModule;
import com.kyvislabs.ntfy.common.scripting.NtfyClientScripts;

public class ClientScriptModule extends AbstractScriptModule {
    private final NtfyClientScripts rpc;
    public ClientScriptModule() {
        rpc = ModuleRPCFactory.create(
            "com.kyvislabs.ntfy",
            NtfyClientScripts.class
        );
    }

    @NoHint
    @Override
    public boolean sendMessageImpl(String serverUrl, String topic, String message, String title, String tags, String priority, String clickAction, String attach, String actions, String icon, String username, String password){
        return rpc.sendMessage(serverUrl, topic, message, title, tags, priority, clickAction, attach, actions, icon, username, password);
    }
}
