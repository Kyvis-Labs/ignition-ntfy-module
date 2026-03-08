package com.kyvislabs.ntfy.gateway.profile;

import com.inductiveautomation.ignition.alarming.notification.AlarmNotificationProfile;
import com.inductiveautomation.ignition.alarming.notification.AlarmNotificationProfileConfig;
import com.inductiveautomation.ignition.alarming.notification.AlarmNotificationProfileExtensionPoint;
import com.inductiveautomation.ignition.common.i18n.LocalizedString;
import com.inductiveautomation.ignition.common.user.ContactType;
import com.inductiveautomation.ignition.gateway.audit.AuditProfileType;
import com.inductiveautomation.ignition.gateway.config.DecodedResource;
import com.inductiveautomation.ignition.gateway.config.ExtensionPointConfig;
import com.inductiveautomation.ignition.gateway.config.ValidationErrors;
import com.inductiveautomation.ignition.gateway.dataroutes.openapi.SchemaUtil;
import com.inductiveautomation.ignition.gateway.model.GatewayContext;
import com.inductiveautomation.ignition.gateway.web.nav.ExtensionPointResourceForm;
import com.inductiveautomation.ignition.gateway.web.nav.WebUiComponent;

import java.util.Optional;

public class NtfyNotificationExtensionPoint
        extends AlarmNotificationProfileExtensionPoint<NtfyNotificationProfileResource> {

    public static final String TYPE_ID = "NtfyType";
    public static final ContactType NTFY =
            new ContactType("Ntfy", new LocalizedString("NtfyNotification.ContactType.Ntfy"));

    public NtfyNotificationExtensionPoint() {
        super(TYPE_ID,
                "NtfyNotification.NtfyNotificationProfileType.Name",
                "NtfyNotification.NtfyNotificationProfileType.Description",
                NtfyNotificationProfileResource.class);

        addReferenceProperty(
                "auditProfileName",
                builder -> builder
                        .value(NtfyNotificationProfileResource::auditProfileName)
                        .targetType(AuditProfileType.RESOURCE_TYPE)
                        .onUpdate((oldResource, newName) ->
                                new NtfyNotificationProfileResource(
                                        oldResource.serverUrl(),
                                        oldResource.ackTopic(),
                                        oldResource.username(),
                                        oldResource.password(),
                                        newName
                                )
                        )
        );
    }

    @Override
    public AlarmNotificationProfile createNewProfile(
            GatewayContext gatewayContext,
            DecodedResource<ExtensionPointConfig<AlarmNotificationProfileConfig, ?>> decodedResource,
            NtfyNotificationProfileResource profileResource) throws Exception {
        return new NtfyNotificationProfile(gatewayContext, decodedResource, profileResource);
    }

    @Override
    protected void validate(NtfyNotificationProfileResource settings, ValidationErrors.Builder errors) {
        super.validate(settings, errors);
    }

    @Override
    public Optional<WebUiComponent> getWebUiComponent(ComponentType type) {
        return Optional.of(
                new ExtensionPointResourceForm(
                        AlarmNotificationProfileConfig.RESOURCE_TYPE,
                        "Alarm Notification Profile",
                        TYPE_ID,
                        SchemaUtil.fromType(AlarmNotificationProfileConfig.class),
                        SchemaUtil.fromType(NtfyNotificationProfileResource.class, builder ->
                                SchemaUtil.buildSecretConfigSchema(builder,
                                        SchemaUtil.fromType(NtfyNotificationProfileResource.class), true)
                        )
                )
        );
    }
}
