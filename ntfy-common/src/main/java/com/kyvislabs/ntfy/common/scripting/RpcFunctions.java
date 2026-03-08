package com.kyvislabs.ntfy.common.scripting;

import com.inductiveautomation.ignition.common.rpc.RpcInterface;
import com.inductiveautomation.ignition.common.rpc.RpcSerializer;
import com.inductiveautomation.ignition.common.rpc.proto.ProtoRpcSerializer;
import kotlin.Metadata;

@RpcInterface(packageId = "ntfy")
public interface RpcFunctions {
    Metadata getGatewayMetadata();

    /**
     * <b>If</b> you have custom classes that aren't explicitly or implicitly serializable and need to have custom
     * behavior, you can do so with a custom ProtoRpcSerializer (or your own RpcSerializer implementation entirely!).
     * Just make sure that the same serializer instance is used on both sides of the RPC operation!
     *
     * @see ProtoRpcSerializer
     * @see RpcSerializer
     */
    RpcSerializer SERIALIZER = ProtoRpcSerializer.newBuilder().build();
}
