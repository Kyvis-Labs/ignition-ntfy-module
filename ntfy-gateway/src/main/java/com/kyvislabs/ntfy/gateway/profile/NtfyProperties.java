package com.kyvislabs.ntfy.gateway.profile;

import com.inductiveautomation.ignition.alarming.common.notification.BasicNotificationProfileProperty;
import com.inductiveautomation.ignition.common.alarming.config.AlarmProperty;
import com.inductiveautomation.ignition.common.alarming.config.BasicAlarmProperty;
import com.inductiveautomation.ignition.common.config.ConfigurationProperty;
import com.inductiveautomation.ignition.common.i18n.LocalizedString;

import java.util.ArrayList;
import java.util.List;

import static com.inductiveautomation.ignition.common.BundleUtil.i18n;

public class NtfyProperties {

    public static final BasicNotificationProfileProperty<String> MESSAGE = new BasicNotificationProfileProperty<>(
            "message",
            "NtfyNotification." + "Properties.Message.DisplayName",
            null,
            String.class
    );

    public static final BasicNotificationProfileProperty<String> THROTTLED_MESSAGE =
            new BasicNotificationProfileProperty<>(
                    "throttledMessage",
                    "NtfyNotification." + "Properties.ThrottledMessage.DisplayName",
                    null,
                    String.class
            );

    public static final BasicNotificationProfileProperty<Long> TIME_BETWEEN_NOTIFICATIONS =
            new BasicNotificationProfileProperty<>(
                    "delayBetweenContact",
                    "NtfyNotification." + "Properties.TimeBetweenNotifications.DisplayName",
                    null,
                    Long.class
            );

    public static final BasicNotificationProfileProperty<String> TITLE = new BasicNotificationProfileProperty<>(
            "title",
            "NtfyNotification." + "Properties.Title.DisplayName",
            null,
            String.class
    );

    public static final BasicNotificationProfileProperty<String> PRIORITY = new BasicNotificationProfileProperty<>(
            "priority",
            "NtfyNotification." + "Properties.Priority.DisplayName",
            null,
            String.class
    );

    public static final BasicNotificationProfileProperty<Boolean> TEST_MODE = new BasicNotificationProfileProperty<>(
            "testMode",
            "NtfyNotification." + "Properties.TestMode.DisplayName",
            null,
            Boolean.class
    );

    public static final BasicNotificationProfileProperty<String> TAGS = new BasicNotificationProfileProperty<>(
        "tags",
        "NtfyNotification.Properties.Tags.DisplayName",
        null,
        String.class
    );

    public static final BasicNotificationProfileProperty<String> CLICK_ACTION = new BasicNotificationProfileProperty<>(
        "clickAction",
        "NtfyNotification.Properties.ClickAction.DisplayName",
        null,
        String.class
    );

    public static final BasicNotificationProfileProperty<String> ATTACH = new BasicNotificationProfileProperty<>(
        "attach",
        "NtfyNotification.Properties.Attach.DisplayName",
        null,
        String.class
    );

    public static final BasicNotificationProfileProperty<String> ACTIONS = new BasicNotificationProfileProperty<>(
        "actions",
        "NtfyNotification.Properties.Actions.DisplayName",
        null,
        String.class
    );

    public static final BasicNotificationProfileProperty<String> ICON = new BasicNotificationProfileProperty<>(
        "icon",
        "NtfyNotification.Properties.Icon.DisplayName",
        null,
        String.class
    );

    /**
     * EXTENDED CONFIG - These are different than the properties above, they are registered for each alarm through the
     * extended config system
     **/

     public static AlarmProperty<String> CUSTOM_TAGS = new BasicAlarmProperty<>("CustomNtfyTags",
            String.class, "",
            "NtfyNotification.Properties.ExtendedConfig.CustomTags",
            "NtfyNotification.Properties.ExtendedConfig.Category",
            "NtfyNotification.Properties.ExtendedConfig.CustomTags.Desc", true, false);

     public static AlarmProperty<String> CUSTOM_TITLE = new BasicAlarmProperty<>("CustomNtfyTitle",
            String.class, "",
            "NtfyNotification.Properties.ExtendedConfig.CustomTitle",
            "NtfyNotification.Properties.ExtendedConfig.Category",
            "NtfyNotification.Properties.ExtendedConfig.CustomTitle.Desc", true, false);

    public static AlarmProperty<String> CUSTOM_MESSAGE = new BasicAlarmProperty<>("CustomNtfyMessage",
            String.class, "",
            "NtfyNotification.Properties.ExtendedConfig.CustomMessage",
            "NtfyNotification.Properties.ExtendedConfig.Category",
            "NtfyNotification.Properties.ExtendedConfig.CustomMessage.Desc", true, false);

    public static AlarmProperty<String> CUSTOM_PRIORITY = new BasicAlarmProperty<>("CustomNtfyPriority",
            String.class, "",
            "NtfyNotification.Properties.ExtendedConfig.CustomPriority",
            "NtfyNotification.Properties.ExtendedConfig.Category",
            "NtfyNotification.Properties.ExtendedConfig.CustomPriority.Desc", true, false);

    static {
        MESSAGE.setExpressionSource(true);
        MESSAGE.setDefaultValue(i18n("NtfyNotification." + "Properties.Message.DefaultValue"));

        TAGS.setExpressionSource(true);
        
        THROTTLED_MESSAGE.setExpressionSource(true);
        THROTTLED_MESSAGE.setDefaultValue(i18n("NtfyNotification." + "Properties.ThrottledMessage.DefaultValue"));

        TIME_BETWEEN_NOTIFICATIONS.setExpressionSource(true);
        TIME_BETWEEN_NOTIFICATIONS.setDefaultValue(i18n("NtfyNotification."
                + "Properties.TimeBetweenNotifications.DefaultValue"));

        TITLE.setExpressionSource(true);

        PRIORITY.setDefaultValue("default");
        List<ConfigurationProperty.Option<String>> priorityOptions = new ArrayList<>();
        priorityOptions.add(new ConfigurationProperty.Option<>("min", new LocalizedString("NtfyNotification.Properties.Priority.min")));
        priorityOptions.add(new ConfigurationProperty.Option<>("low", new LocalizedString("NtfyNotification.Properties.Priority.low")));
        priorityOptions.add(new ConfigurationProperty.Option<>("default", new LocalizedString("NtfyNotification.Properties.Priority.default")));
        priorityOptions.add(new ConfigurationProperty.Option<>("high", new LocalizedString("NtfyNotification.Properties.Priority.high")));
        priorityOptions.add(new ConfigurationProperty.Option<>("max", new LocalizedString("NtfyNotification.Properties.Priority.max")));
        PRIORITY.setOptions(priorityOptions);

        TEST_MODE.setDefaultValue(false);
        List<ConfigurationProperty.Option<Boolean>> options = new ArrayList<>();
        options.add(new ConfigurationProperty.Option<>(true, new LocalizedString("words.yes")));
        options.add(new ConfigurationProperty.Option<>(false, new LocalizedString("words.no")));
        TEST_MODE.setOptions(options);

        CLICK_ACTION.setExpressionSource(true);
        ATTACH.setExpressionSource(true);
        ACTIONS.setExpressionSource(true);
        ICON.setExpressionSource(true);

    }

}
