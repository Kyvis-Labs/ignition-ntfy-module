package com.kyvislabs.ntfy.common.scripting;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.python.core.PyObject;

import com.inductiveautomation.ignition.common.BundleUtil;
import com.inductiveautomation.ignition.common.script.PyArgParser;
import com.inductiveautomation.ignition.common.script.builtin.KeywordArgs;
import com.inductiveautomation.ignition.common.script.hints.JythonElement;
import com.inductiveautomation.ignition.common.script.hints.ScriptArg;

public abstract class AbstractScriptModule {
    static {
        BundleUtil.get().addBundle(
            AbstractScriptModule.class.getSimpleName(),
            AbstractScriptModule.class.getClassLoader(),
            AbstractScriptModule.class.getName().replace('.', '/')
        );
    }

    public Logger logger = LoggerFactory.getLogger("ntfy.scripting.client");

    @KeywordArgs(
        names={"serverUrl", "topic", "message", "title", "tags", "priority", "clickAction", "attach", "actions", "icon", "username", "password"},
        types={String.class, String.class, String.class, String.class, String.class, String.class, String.class, String.class, String.class, String.class, String.class, String.class}
    )
    @JythonElement(docBundlePrefix = "AbstractScriptModule")
    public boolean sendMessage(PyObject[] pyArgs, String[] keywords) throws Exception {
        PyArgParser args = PyArgParser.parseArgs(
            pyArgs, keywords,
            new String[]{"serverUrl", "topic", "message", "title", "tags", "priority", "clickAction", "attach", "actions", "icon", "username", "password"},
            new Class<?>[]{String.class, String.class, String.class, String.class, String.class, String.class, String.class, String.class, String.class, String.class, String.class, String.class},
            "sendMessage"
        );

        String serverUrl = args.requireString("serverUrl");
        String topic = args.requireString("topic");
        String message = args.requireString("message");
        String title = args.getString("title").orElse("");
        String tags = args.getString("tags").orElse("");
        String priority = args.getString("priority").orElse("");
        String clickAction = args.getString("clickAction").orElse("");
        String attach = args.getString("attach").orElse("");
        String actions = args.getString("actions").orElse("");
        String icon = args.getString("icon").orElse("");
        String username = args.getString("username").orElse("");
        String password = args.getString("password").orElse("");

        return sendMessageImpl(serverUrl, topic, message, title, tags, priority, clickAction, attach, actions, icon, username, password);
    }

    public boolean sendMessage(String serverUrl, String topic, String message, String title, String tags,
            String priority, String clickAction, String attach, String actions, String icon, String username,
            String password) {
        return sendMessageImpl(serverUrl, topic, message, title, tags, priority, clickAction, attach, actions, icon, username, password);
    }

    protected abstract boolean sendMessageImpl(String serverUrl, String topic, String message, String title,
            String tags, String priority, String clickAction, String attach, String actions, String icon,
            String username, String password);
}
