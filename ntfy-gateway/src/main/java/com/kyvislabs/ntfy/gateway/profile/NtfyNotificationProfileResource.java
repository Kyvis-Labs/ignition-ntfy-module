package com.kyvislabs.ntfy.gateway.profile;

import com.inductiveautomation.ignition.gateway.dataroutes.openapi.annotations.*;
import com.inductiveautomation.ignition.gateway.secrets.Secret;
import com.inductiveautomation.ignition.gateway.secrets.SecretConfig;
import com.inductiveautomation.ignition.gateway.web.nav.FormFieldType;

import javax.annotation.Nullable;

public record NtfyNotificationProfileResource(

        @FormCategory("API")
        @Label("Server URL")
        @FormField(FormFieldType.TEXT)
        @DefaultValue("")
        @DescriptionKey("NtfyNotificationProfileSettings.ServerUrl.Desc")
        String ServerUrl,

        @FormCategory("API")
        @Label("Ack Topic")
        @FormField(FormFieldType.TEXT)
        @DefaultValue("")
        @DescriptionKey("NtfyNotificationProfileSettings.AckTopic.Desc")
        String AckTopic,

        @FormCategory("Authentication")
        @Label("Username")
        @FormField(FormFieldType.TEXT)
        @DefaultValue("")
        String Username,

        @FormCategory("Authentication")
        @Label("Password")
        @FormField(FormFieldType.SECRET)
        @DefaultValue("")
        SecretConfig Password,

        @Nullable
        @FormCategory("Audit")
        @Label("Audit Profile")
        @FormField(FormFieldType.REFERENCE)
        @FormReferenceType("ignition/audit-profile")
        @IsNullable
        @DefaultValue("null")
        @DescriptionKey("NtfyNotificationProfileSettings.AuditProfile.Desc")
        String auditProfileName

)

{
}
