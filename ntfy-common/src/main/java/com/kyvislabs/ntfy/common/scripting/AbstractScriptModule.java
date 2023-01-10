package com.kyvislabs.ntfy.common.scripting;

import org.apache.log4j.Logger;
import org.python.core.PyObject;
import org.python.netty.util.internal.StringUtil;

import com.inductiveautomation.ignition.common.BundleUtil;
import com.inductiveautomation.ignition.common.script.builtin.KeywordArgs;
import com.inductiveautomation.ignition.common.script.builtin.PyArgumentMap;
import com.inductiveautomation.ignition.common.script.hints.NoHint;
import com.inductiveautomation.ignition.common.script.hints.ScriptFunction;

public abstract class AbstractScriptModule implements NtfyClientScripts 
{
    static {
        BundleUtil.get().addBundle(
            AbstractScriptModule.class.getSimpleName(),
            AbstractScriptModule.class.getClassLoader(),
            AbstractScriptModule.class.getName().replace('.', '/')
        );
    }
    public Logger logger = Logger.getLogger("ntfy.scripting.client");
    @ScriptFunction(docBundlePrefix = "AbstractScriptModule")
    @KeywordArgs(
        names={"serverUrl", "topic", "message","title","tags","priority","clickAction","attach","actions","icon","username","password"}, 
        types={String.class, String.class, String.class, String.class, String.class, String.class, String.class, String.class, String.class, String.class, String.class, String.class}
    )
    public boolean sendMessage(PyObject[] pyArgs, String[] keywords) throws Exception {
            PyArgumentMap args = PyArgumentMap.interpretPyArgs(pyArgs, keywords, AbstractScriptModule.class, "sendMessage");    

            String serverUrl = args.getStringArg("serverUrl");
            if (StringUtil.isNullOrEmpty(serverUrl)){
                logger.error("Invalid Server URL");
                return false;
            }

            String topic = args.getStringArg("topic");
            if (StringUtil.isNullOrEmpty(topic)){
                logger.error("Invalid Topic");
                return false;

            }

            String message = args.getStringArg("message");
            if (StringUtil.isNullOrEmpty(message)){
                logger.error("Invalid Message");
                return false;

            }

            String title = args.getStringArg("title","");
            String tags = args.getStringArg("tags");
            String priority = args.getStringArg("priority");
            String clickAction = args.getStringArg("clickAction");
            String attach = args.getStringArg("attach");
            String actions = args.getStringArg("actions");
            String icon = args.getStringArg("icon");
            String username = args.getStringArg("username");
            String password = args.getStringArg("password");
            return sendMessageImpl(serverUrl, topic, message, title, tags, priority, clickAction, attach, actions, icon, username, password);
    }

    @NoHint
    @Override
    public boolean sendMessage(String serverUrl, String topic, String message, String title, String tags,
            String priority, String clickAction, String attach, String actions, String icon, String username,
            String password) {
        return sendMessageImpl(serverUrl, topic, message, title, tags, priority, clickAction, attach, actions, icon, username, password);
    }

    @NoHint
    protected abstract boolean sendMessageImpl(String serverUrl, String topic, String message, String title, String tags, String priority, String clickAction, String attach, String actions, String icon, String username, String password);
}