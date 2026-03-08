package com.kyvislabs.ntfy.gateway.profile;

import com.inductiveautomation.ignition.alarming.notification.AlarmNotificationProfileRecord;
import com.inductiveautomation.ignition.gateway.audit.AuditProfileRecord;
import com.inductiveautomation.ignition.gateway.localdb.persistence.*;

/**
 * Legacy configuration record, kept for backwards compatibility with 8.1 installations.
 * The migration strategy in GatewayHook converts these records to the new
 * NtfyNotificationProfileResource format.
 */
@SuppressWarnings("deprecation")
public class NtfyNotificationProfileSettings extends PersistentRecord {

    public static final RecordMeta<NtfyNotificationProfileSettings> META =
            new RecordMeta<>(
                    NtfyNotificationProfileSettings.class,
                    "NtfyNotificationProfileSettings"
            );
    public static final IdentityField Id = new IdentityField(META);
    public static final LongField ProfileId = new LongField(META, "ProfileId");
    public static final ReferenceField<AlarmNotificationProfileRecord> Profile = new ReferenceField<>(
            META,
            AlarmNotificationProfileRecord.META,
            "Profile",
            ProfileId);

    public static final StringField ServerUrl = new StringField(META, "ServerUrl");
    public static final StringField AckTopic = new StringField(META, "AckTopic");

    public static final StringField Username = new StringField(META, "Username");
    public static final StringField Password = new StringField(META, "Password");

    public static final LongField AuditProfileId = new LongField(META, "AuditProfileId");
    public static final ReferenceField<AuditProfileRecord> AuditProfile = new ReferenceField<>(
            META, AuditProfileRecord.META, "AuditProfile", AuditProfileId);

    @Override
    public RecordMeta<?> getMeta() {
        return META;
    }

    public String getAuditProfileName() {
        AuditProfileRecord rec = findReference(AuditProfile);
        return rec == null ? null : rec.getName();
    }

    public String getServerUrl() {
        return getString(ServerUrl);
    }

    public String getAckTopic() {
        return getString(AckTopic);
    }

    public String getUsername() {
        return getString(Username);
    }

    public String getPassword() {
        return getString(Password);
    }
}
