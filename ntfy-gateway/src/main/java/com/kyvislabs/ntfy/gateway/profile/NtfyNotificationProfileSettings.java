package com.kyvislabs.ntfy.gateway.profile;

import com.inductiveautomation.ignition.alarming.notification.AlarmNotificationProfileRecord;
import com.inductiveautomation.ignition.gateway.audit.AuditProfileRecord;
import com.inductiveautomation.ignition.gateway.localdb.persistence.*;
import simpleorm.dataset.SFieldFlags;

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

    public static final StringField ServerUrl = new StringField(META, "ServerUrl", SFieldFlags.SMANDATORY);
    public static final StringField CallbackUrl = new StringField(META, "CallbackUrl");

    static final Category API = new Category("NtfyNotificationProfileSettings.Category.API", 1)
            .include(ServerUrl,CallbackUrl);

    public static final StringField Username = new StringField(META,"Username");
    public static final StringField Password = new StringField(META,"Password");

    static final Category Authentication = new Category("NtfyNotificationProfileSettings.Category.Authentication",2)
        .include(Username,Password);

        public static final LongField AuditProfileId = new LongField(META, "AuditProfileId");
    public static final ReferenceField<AuditProfileRecord> AuditProfile = new ReferenceField<>(
            META, AuditProfileRecord.META, "AuditProfile", AuditProfileId);


    static final Category Auditing = new Category("NtfyNotificationProfileSettings.Category.Auditing", 3)
            .include(AuditProfile);

    static {
        Profile.getFormMeta().setVisible(false);
    }

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

    public String getCallbackUrl() {
        return getString(CallbackUrl);
    }

    public String getUsername() {
        return getString(Username);
    }

    public String getPassword() {
        return getString(Password);
    }
}

