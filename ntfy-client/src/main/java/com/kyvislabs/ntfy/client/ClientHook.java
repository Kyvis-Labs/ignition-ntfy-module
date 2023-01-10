package com.kyvislabs.ntfy.client;

import com.inductiveautomation.ignition.common.script.ScriptManager;
import com.inductiveautomation.ignition.common.script.hints.PropertiesFileDocProvider;
import com.inductiveautomation.vision.api.client.AbstractClientModuleHook;

public class ClientHook extends AbstractClientModuleHook {

    @Override
    public void initializeScriptManager(ScriptManager manager) {
        super.initializeScriptManager(manager);

        manager.addScriptModule(
            "system.ntfy",
            new ClientScriptModule(),
            new PropertiesFileDocProvider()
        );
    }

}