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


/**
 * This is an example of implementing an existing "extension point" from Ignition; specifically, an alarm notification
 * profile.
 * <p>
 * Extension points are the most common way for modules to interface smoothly with Ignition, and knowing which extension
 * point you are extending is a core part of working with Ignition.
 */
public class NtfyNotificationExtensionPoint
        extends AlarmNotificationProfileExtensionPoint<NtfyNotificationProfileResource> {
    public static final String TYPE_ID = "NtfyType";
    public static final ContactType NTFY =
            new ContactType("Ntfy", new LocalizedString("NtfyNotification.ContactType.Ntfy"));

    public NtfyNotificationExtensionPoint() {
        super(TYPE_ID,
                "NtfyNotification.SlackNotificationProfileType.DisplayName",
                "NtfyNotification.SlackNotificationProfileType.Description",
                NtfyNotificationProfileResource.class);

        /*
         Add a "reference property", so that the gateway knows we're using an audit profile's name in our config
         If something tries to delete that audit profile, it will be prevented
         If that audit profile is renamed, it will update our config (per the lambda below)
        */
        addReferenceProperty(
                "auditProfileName",
                builder -> builder
                        .value(NtfyNotificationProfileResource::auditProfileName)
                        .targetType(AuditProfileType.RESOURCE_TYPE)
                        .onUpdate((oldResource, newName) ->
                                new NtfyNotificationProfileResource(oldResource.ServerUrl(), oldResource.AckTopic(), oldResource.Username(), oldResource.Password(), newName)
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
        /*
         Optionally add validation to an incoming configuration object
         These error messages will be conveyed back to the standard web UI automatically
        */
        // errors.requireNotNull("someField", settings.auditProfileName());
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
                        SchemaUtil.fromType(NtfyNotificationProfileResource.class)
                )
        );
    }

}
