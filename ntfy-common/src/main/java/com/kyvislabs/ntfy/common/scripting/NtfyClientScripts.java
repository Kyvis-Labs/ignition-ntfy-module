package com.kyvislabs.ntfy.common.scripting;

public interface NtfyClientScripts {
    public boolean sendMessage(String serverUrl, String topic, String message, String title, String tags, String priority, String clickAction, String attach, String actions, String icon, String username, String password);
}