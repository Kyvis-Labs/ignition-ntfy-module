package com.kyvislabs.ntfy.gateway.profile;

import com.inductiveautomation.ignition.alarming.notification.AlarmNotificationProfile;
import com.inductiveautomation.ignition.alarming.notification.AlarmNotificationProfileRecord;
import com.inductiveautomation.ignition.alarming.notification.AlarmNotificationProfileType;
import com.inductiveautomation.ignition.common.i18n.LocalizedString;
import com.inductiveautomation.ignition.common.user.ContactType;
import com.inductiveautomation.ignition.gateway.localdb.persistence.PersistentRecord;
import com.inductiveautomation.ignition.gateway.localdb.persistence.RecordMeta;
import com.inductiveautomation.ignition.gateway.model.GatewayContext;

public class NtfyNotificationProfileType extends AlarmNotificationProfileType {
    public static final String TYPE_ID = "NtfyType";
    public static final ContactType NTFY =
            new ContactType("Ntfy", new LocalizedString("NtfyNotification.ContactType.Ntfy"));

    public NtfyNotificationProfileType() {
        super(TYPE_ID,
                "NtfyNotification." + "NtfyNotificationProfileType.Name",
                "NtfyNotification." + "NtfyNotificationProfileType.Description");
    }

    @Override
    public RecordMeta<? extends PersistentRecord> getSettingsRecordType() {
        return NtfyNotificationProfileSettings.META;
    }

    @Override
    public AlarmNotificationProfile createNewProfile(GatewayContext context,
                                                     AlarmNotificationProfileRecord profileRecord) throws Exception {
        NtfyNotificationProfileSettings settings = findProfileSettingsRecord(context, profileRecord);

        if (settings == null) {
            throw new Exception(
                    String.format("Couldn't find settings record for profile '%s'.", profileRecord.getName()));
        }

        return new NtfyNotificationProfile(context, profileRecord, settings);
    }

}
