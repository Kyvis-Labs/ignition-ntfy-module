package com.kyvislabs.ntfy.common.scripting;

import com.inductiveautomation.ignition.common.rpc.RpcInterface;
import com.inductiveautomation.ignition.common.rpc.RpcSerializer;
import com.inductiveautomation.ignition.common.rpc.proto.ProtoRpcSerializer;

@RpcInterface(packageId = "ntfy-scripting")
public interface NtfyClientScripts {
    boolean sendMessage(String serverUrl, String topic, String message, String title, String tags,
                        String priority, String clickAction, String attach, String actions, String icon,
                        String username, String password);

    RpcSerializer SERIALIZER = ProtoRpcSerializer.newBuilder().build();
}
