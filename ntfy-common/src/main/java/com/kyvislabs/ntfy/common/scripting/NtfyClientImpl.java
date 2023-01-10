package com.kyvislabs.ntfy.common.scripting;


import com.kyvislabs.ntfy.common.NtfyClient;

public class NtfyClientImpl extends AbstractScriptModule {

    private NtfyClient client = new NtfyClient();
    @Override
    protected boolean sendMessageImpl(String serverUrl, String topic, String message, String title, String tags, String priority, String clickAction, String attach, String actions, String icon, String username, String password) {
        logger.debug("Sending Message");
        return client.sendMessage(serverUrl, topic, message, title, tags, priority, clickAction, attach, actions, icon, username, password);
    }

}
