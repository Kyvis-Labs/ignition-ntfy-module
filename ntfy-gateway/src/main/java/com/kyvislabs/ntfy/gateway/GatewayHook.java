package com.kyvislabs.ntfy.gateway;

import com.inductiveautomation.ignition.alarming.notification.AlarmNotificationProfileConfig;
import com.inductiveautomation.ignition.alarming.notification.AlarmNotificationProfileRecord;
import com.inductiveautomation.ignition.common.BundleUtil;
import com.inductiveautomation.ignition.common.licensing.LicenseState;
import com.inductiveautomation.ignition.common.script.ScriptManager;
import com.inductiveautomation.ignition.common.script.hints.PropertiesFileDocProvider;
import com.inductiveautomation.ignition.gateway.config.ExtensionPoint;
import com.inductiveautomation.ignition.gateway.config.migration.ExtensionPointRecordMigrationStrategy;
import com.inductiveautomation.ignition.gateway.config.migration.IdbMigrationStrategy;
import com.inductiveautomation.ignition.gateway.model.AbstractGatewayModuleHook;
import com.inductiveautomation.ignition.gateway.model.GatewayContext;
import com.inductiveautomation.ignition.gateway.rpc.GatewayRpcImplementation;
import com.kyvislabs.ntfy.common.scripting.NtfyClientImpl;
import com.kyvislabs.ntfy.common.scripting.NtfyClientScripts;
import com.kyvislabs.ntfy.gateway.profile.NtfyNotificationExtensionPoint;
import com.kyvislabs.ntfy.gateway.profile.NtfyNotificationProfileSettings;
import com.kyvislabs.ntfy.gateway.profile.NtfyProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Optional;

import static com.kyvislabs.ntfy.gateway.profile.NtfyNotificationExtensionPoint.NTFY;

public class GatewayHook extends AbstractGatewayModuleHook {
    public static final String MODULE_ID = "com.kyvislabs.ntfy";
    private final Logger logger = LoggerFactory.getLogger("Ntfy.Gateway.Hook");

    private GatewayContext gatewayContext;
    private final NtfyClientImpl ntfyClient = new NtfyClientImpl();

    @Override
    public void setup(GatewayContext context) {
        this.gatewayContext = context;
        BundleUtil.get().addBundle("NtfyNotification", getClass(), "NtfyNotification");

        context.getAlarmManager()
                .registerExtendedConfigProperties(MODULE_ID, NtfyProperties.CUSTOM_TITLE);
        context.getAlarmManager()
                .registerExtendedConfigProperties(MODULE_ID, NtfyProperties.CUSTOM_MESSAGE);
        context.getAlarmManager()
                .registerExtendedConfigProperties(MODULE_ID, NtfyProperties.CUSTOM_PRIORITY);
        context.getAlarmManager()
                .registerExtendedConfigProperties(MODULE_ID, NtfyProperties.CUSTOM_TAGS);
        context.getAlarmManager()
                .registerExtendedConfigProperties(MODULE_ID, NtfyProperties.CUSTOM_CLICK);
        context.getAlarmManager()
                .registerExtendedConfigProperties(MODULE_ID, NtfyProperties.CUSTOM_ATTACH);
        context.getAlarmManager()
                .registerExtendedConfigProperties(MODULE_ID, NtfyProperties.CUSTOM_ACTIONS);
        context.getAlarmManager()
                .registerExtendedConfigProperties(MODULE_ID, NtfyProperties.CUSTOM_ICON);

        context.getUserSourceManager().registerContactType(NTFY);
    }

    @Override
    public void startup(LicenseState licenseState) {
    }

    @Override
    public void shutdown() {
        gatewayContext.getUserSourceManager().unregisterContactType(NTFY);
        BundleUtil.get().removeBundle("NtfyNotification");
    }

    @SuppressWarnings("deprecation")
    @Override
    public List<IdbMigrationStrategy> getRecordMigrationStrategies() {
        return List.of(ExtensionPointRecordMigrationStrategy
                .newBuilder(NtfyNotificationExtensionPoint.TYPE_ID)
                .resourceType(AlarmNotificationProfileConfig.RESOURCE_TYPE)
                .profileMeta(AlarmNotificationProfileRecord.META)
                .settingsRecordForeignKey(NtfyNotificationProfileSettings.Profile)
                .settingsMeta(NtfyNotificationProfileSettings.META)
                .build()
        );
    }

    @Override
    public List<? extends ExtensionPoint<?>> getExtensionPoints() {
        return List.of(new NtfyNotificationExtensionPoint());
    }

    @Override
    public boolean isMakerEditionCompatible() {
        return true;
    }

    @Override
    public boolean isFreeModule() {
        return true;
    }

    @Override
    public void initializeScriptManager(ScriptManager manager) {
        super.initializeScriptManager(manager);
        manager.addScriptModule("system.ntfy", ntfyClient, new PropertiesFileDocProvider());
    }

    @Override
    public Optional<GatewayRpcImplementation> getRpcImplementation() {
        return Optional.of(GatewayRpcImplementation.of(
                NtfyClientScripts.SERIALIZER,
                ntfyClient
        ));
    }
}
