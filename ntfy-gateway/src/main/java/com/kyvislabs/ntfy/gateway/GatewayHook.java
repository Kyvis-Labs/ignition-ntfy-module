package com.kyvislabs.ntfy.gateway;

import com.inductiveautomation.ignition.alarming.AlarmNotificationContext;
import com.inductiveautomation.ignition.alarming.common.ModuleMeta;
import com.inductiveautomation.ignition.common.BundleUtil;
import com.inductiveautomation.ignition.common.licensing.LicenseState;
import com.inductiveautomation.ignition.gateway.model.AbstractGatewayModuleHook;
import com.inductiveautomation.ignition.gateway.model.GatewayContext;
import com.inductiveautomation.ignition.gateway.services.ModuleServiceConsumer;
import com.kyvislabs.ntfy.gateway.profile.NtfyNotificationProfileSettings;
import com.kyvislabs.ntfy.gateway.profile.NtfyNotificationProfileType;
import com.kyvislabs.ntfy.gateway.profile.NtfyProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class GatewayHook extends AbstractGatewayModuleHook implements ModuleServiceConsumer {
    public static final String MODULE_ID = "com.kyvislabs.ntfy";
    private final Logger logger = LoggerFactory.getLogger("Ntfy.Gateway.Hook");

    protected static GatewayContext gatewayContext;
    private volatile AlarmNotificationContext notificationContext;

    @Override
    public void setup(GatewayContext gatewayContext) {
        GatewayHook.gatewayContext = gatewayContext;
        BundleUtil.get().addBundle("NtfyNotification", getClass(), "NtfyNotification");

        gatewayContext.getModuleServicesManager().subscribe(AlarmNotificationContext.class, this);

        gatewayContext.getAlarmManager()
                .registerExtendedConfigProperties(ModuleMeta.MODULE_ID, NtfyProperties.CUSTOM_TITLE);

        gatewayContext.getAlarmManager()
                .registerExtendedConfigProperties(ModuleMeta.MODULE_ID, NtfyProperties.CUSTOM_MESSAGE);

        gatewayContext.getAlarmManager()
                .registerExtendedConfigProperties(ModuleMeta.MODULE_ID, NtfyProperties.CUSTOM_PRIORITY);

        gatewayContext.getAlarmManager()
                .registerExtendedConfigProperties(ModuleMeta.MODULE_ID, NtfyProperties.CUSTOM_TAGS);
                
        gatewayContext.getUserSourceManager().registerContactType(NtfyNotificationProfileType.NTFY);

        gatewayContext.getWebResourceManager().addServlet("ntfy", NtfyServlet.class);

        try {
            gatewayContext.getSchemaUpdater().updatePersistentRecords(NtfyNotificationProfileSettings.META);
        } catch (Exception e) {
            logger.error("Error configuring internal database", e);
        }
    }

    @Override
    public void notifyLicenseStateChanged(LicenseState licenseState) {

    }

    @Override
    public void startup(LicenseState licenseState) {
    }

    @Override
    public void shutdown() {
        gatewayContext.getModuleServicesManager().unsubscribe(AlarmNotificationContext.class, this);

        if (notificationContext != null) {
            try {
                notificationContext.getAlarmNotificationManager().removeAlarmNotificationProfileType(
                        new NtfyNotificationProfileType());
            } catch (Exception e) {
                logger.error("Error removing notification profile.", e);
            }
        }
        gatewayContext.getWebResourceManager().removeServlet("ntfy");
        BundleUtil.get().removeBundle("NtfyNotification");
        BundleUtil.get().removeBundle("NtfyNotificationProfileSettings");
    }

    @Override
    public void serviceReady(Class<?> serviceClass) {
        if (serviceClass == AlarmNotificationContext.class) {
            notificationContext = gatewayContext.getModuleServicesManager()
                    .getService(AlarmNotificationContext.class);

            try {
                notificationContext.getAlarmNotificationManager().addAlarmNotificationProfileType(
                        new NtfyNotificationProfileType());
            } catch (Exception e) {
                logger.error("Error adding notification profile.", e);
            }
        }
    }

    @Override
    public void serviceShutdown(Class<?> arg0) {
        notificationContext = null;
    }

    @Override
    public boolean isMakerEditionCompatible() {
        return true;
    }

    @Override
    public boolean isFreeModule() {
        return true;
    }
}
