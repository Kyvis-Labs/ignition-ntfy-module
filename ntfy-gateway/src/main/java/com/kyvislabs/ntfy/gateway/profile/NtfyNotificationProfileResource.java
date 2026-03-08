package com.kyvislabs.ntfy.gateway.profile;

import com.inductiveautomation.ignition.gateway.dataroutes.openapi.annotations.*;
import com.inductiveautomation.ignition.gateway.secrets.SecretConfig;
import com.inductiveautomation.ignition.gateway.web.nav.FormFieldType;

import javax.annotation.Nullable;

public record NtfyNotificationProfileResource(
        @FormCategory("API Settings")
        @Label("Server URL")
        @FormField(FormFieldType.TEXT)
        @Required
        @DefaultValue("")
        @DescriptionKey("NtfyNotificationProfileSettings.ServerUrl.Description")
        String serverUrl,

        @FormCategory("API Settings")
        @Label("Acknowledgement Topic")
        @FormField(FormFieldType.TEXT)
        @DefaultValue("")
        @DescriptionKey("NtfyNotificationProfileSettings.AckTopic.Description")
        String ackTopic,

        @FormCategory("Authentication")
        @Label("Username")
        @FormField(FormFieldType.TEXT)
        @DefaultValue("")
        @DescriptionKey("NtfyNotificationProfileSettings.Username.Description")
        String username,

        @Nullable
        @FormCategory("Authentication")
        @Label("Password")
        @FormField(FormFieldType.SECRET)
        @IsNullable
        @DefaultValue("null")
        @DescriptionKey("NtfyNotificationProfileSettings.Password.Description")
        SecretConfig password,

        @Nullable
        @FormCategory("Auditing")
        @Label("Audit Profile")
        @FormField(FormFieldType.REFERENCE)
        @FormReferenceType("ignition/audit-profile")
        @IsNullable
        @DefaultValue("null")
        @DescriptionKey("NtfyNotificationProfileSettings.AuditProfileName.Description")
        String auditProfileName
) {
}
