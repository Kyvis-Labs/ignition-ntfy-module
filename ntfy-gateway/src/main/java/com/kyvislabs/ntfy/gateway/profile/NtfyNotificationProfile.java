package com.kyvislabs.ntfy.gateway.profile;

import com.inductiveautomation.ignition.alarming.common.notification.BasicNotificationProfileProperty;
import com.inductiveautomation.ignition.alarming.common.notification.NotificationProfileProperty;
import com.inductiveautomation.ignition.alarming.notification.AlarmNotificationProfile;
import com.inductiveautomation.ignition.alarming.notification.AlarmNotificationProfileConfig;
import com.inductiveautomation.ignition.alarming.notification.NotificationContext;
import com.inductiveautomation.ignition.common.TypeUtilities;
import com.inductiveautomation.ignition.common.WellKnownPathTypes;
import com.inductiveautomation.ignition.common.alarming.AlarmEvent;
import com.inductiveautomation.ignition.common.audit.AuditRecord;
import com.inductiveautomation.ignition.common.config.FallbackPropertyResolver;
import com.inductiveautomation.ignition.common.expressions.parsing.Parser;
import com.inductiveautomation.ignition.common.expressions.parsing.StringParser;
import com.inductiveautomation.ignition.common.model.ApplicationScope;
import com.inductiveautomation.ignition.common.model.values.QualifiedValue;
import com.inductiveautomation.ignition.common.sqltags.model.types.DataQuality;
import com.inductiveautomation.ignition.common.user.ContactInfo;
import com.inductiveautomation.ignition.common.user.ContactType;
import com.inductiveautomation.ignition.common.user.User;
import com.inductiveautomation.ignition.common.util.LoggerEx;
import com.inductiveautomation.ignition.gateway.audit.AuditProfile;
import com.inductiveautomation.ignition.gateway.audit.AuditRecordBuilder;
import com.inductiveautomation.ignition.gateway.config.DecodedResource;
import com.inductiveautomation.ignition.gateway.config.ExtensionPointConfig;
import com.inductiveautomation.ignition.gateway.expressions.AlarmEventCollectionExpressionParseContext;
import com.inductiveautomation.ignition.gateway.expressions.FormattedExpressionParseContext;
import com.inductiveautomation.ignition.gateway.model.GatewayContext;
import com.inductiveautomation.ignition.gateway.model.ProfileStatus;
import com.inductiveautomation.ignition.gateway.secrets.Secret;
import com.inductiveautomation.ignition.gateway.secrets.SecretConfig;
import com.kyvislabs.ntfy.common.NtfyClient;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.MDC;

import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

import static com.kyvislabs.ntfy.gateway.profile.NtfyNotificationExtensionPoint.NTFY;

public class NtfyNotificationProfile implements AlarmNotificationProfile {

    private final GatewayContext context;
    private final String auditProfileName;
    private final String profileName;
    private final String serverUrl;
    private final String ackTopic;
    private final String username;
    private final String password;
    private final ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor();
    private volatile ProfileStatus profileStatus = ProfileStatus.UNKNOWN;
    private final LoggerEx log;
    private NtfyAckSubscriber ackSubscriber;
    private final NtfyClient ntfyClient = new NtfyClient();

    private Map<String, String> contextMap;

    public NtfyNotificationProfile(GatewayContext context,
                                   DecodedResource<ExtensionPointConfig<AlarmNotificationProfileConfig, ?>> profileRecord,
                                   NtfyNotificationProfileResource settingsRecord) {
        this.context = context;
        this.profileName = profileRecord.name();
        this.serverUrl = settingsRecord.serverUrl();
        this.ackTopic = settingsRecord.ackTopic();
        this.username = settingsRecord.username();
        SecretConfig passwordConfig = settingsRecord.password();
        String resolvedPassword = null;
        if (passwordConfig != null) {
            try {
                Secret<?> secret = Secret.create(context, passwordConfig);
                resolvedPassword = secret.getPlaintext().getAsString();
            } catch (Exception e) {
                LoggerEx.newBuilder().build(getClass()).error("Error resolving password secret", e);
            }
        }
        this.password = resolvedPassword;
        this.auditProfileName = settingsRecord.auditProfileName();
        this.log = LoggerEx.newBuilder().build(String.format("Ntfy.%s.Profile", this.profileName));
    }

    @Override
    public String getName() {
        return profileName;
    }

    @Override
    public String getProfileType() {
        return NtfyNotificationExtensionPoint.TYPE_ID;
    }

    @Override
    public Collection<NotificationProfileProperty<?>> getProperties() {
        return List.of(
                NtfyProperties.MESSAGE,
                NtfyProperties.THROTTLED_MESSAGE,
                NtfyProperties.TITLE,
                NtfyProperties.PRIORITY,
                NtfyProperties.TAGS,
                NtfyProperties.CLICK_ACTION,
                NtfyProperties.ACTIONS,
                NtfyProperties.ATTACH,
                NtfyProperties.ICON,
                NtfyProperties.TEST_MODE);
    }

    @Override
    public ProfileStatus getStatus() {
        return profileStatus;
    }

    @Override
    public Collection<ContactType> getSupportedContactTypes() {
        return List.of(NTFY);
    }

    @Override
    public void onShutdown() {
        executor.shutdown();
        if (ackSubscriber != null) {
            ackSubscriber.getExecutor().shutdownNow();
        }
    }

    @Override
    public void setContextMap(Map<String, String> contextMap) {
        this.contextMap = contextMap;
    }

    @Override
    public void onStartup() {
        profileStatus = ProfileStatus.RUNNING;
        if (!StringUtils.isBlank(ackTopic)) {
            this.ackSubscriber = new NtfyAckSubscriber(context, profileName, serverUrl, ackTopic);
        }
    }

    @Override
    public void sendNotification(final NotificationContext notificationContext) {
        executor.execute(() -> {
            if (contextMap != null) {
                MDC.setContextMap(contextMap);
            } else {
                MDC.clear();
            }

            var ntfyContactInfos = notificationContext.getUser().getContactInfo().stream()
                    .filter(contactInfo -> NTFY.getContactType().equals(contactInfo.getContactType()))
                    .toList();

            String message = evaluateStringExpression(notificationContext, NtfyProperties.MESSAGE);
            String title = evaluateStringExpression(notificationContext, NtfyProperties.TITLE);
            String priority = evaluateStringExpression(notificationContext, NtfyProperties.PRIORITY);
            String tags = evaluateStringExpression(notificationContext, NtfyProperties.TAGS);
            String clickAction = evaluateStringExpression(notificationContext, NtfyProperties.CLICK_ACTION);
            String attach = evaluateStringExpression(notificationContext, NtfyProperties.ATTACH);
            String actions = evaluateStringExpression(notificationContext, NtfyProperties.ACTIONS);
            String icon = evaluateStringExpression(notificationContext, NtfyProperties.ICON);
            boolean testMode = notificationContext.getNonNull(NtfyProperties.TEST_MODE, true);

            actions = generateActionsString(notificationContext, actions);

            boolean success = true;
            if (testMode) {
                log.infof(
                        """
                                THIS PROFILE IS RUNNING IN TEST MODE. The following WOULD have been sent:
                                Message: %s, Title=%s""",
                        message, title);

                notificationContext.notificationDone();
                return;
            }

            for (ContactInfo contactInfo : ntfyContactInfos) {
                String topic = contactInfo.getValue();

                log.debugf(
                        "Attempting to send an alarm notification to topic %s via %s [message=%s, title=%s]",
                        notificationContext.getUser(),
                        topic,
                        message,
                        title);

                success = ntfyClient.sendMessage(serverUrl, topic, message, title, tags, priority,
                        clickAction, attach, actions, icon, username, password);
                audit(success, String.format("Ntfy message to topic %s", topic), notificationContext);
            }

            notificationContext.notificationDone();
        });
    }

    private void audit(boolean success, String eventDesc, NotificationContext notificationContext) {
        if (!StringUtils.isBlank(auditProfileName)) {
            try {
                AuditProfile p = context.getAuditManager().getProfile(auditProfileName);
                if (p == null) {
                    return;
                }
                for (AlarmEvent event : notificationContext.getAlarmEvents()) {
                    AuditRecord r = new AuditRecordBuilder()
                            .setAction(eventDesc)
                            .setActionTarget(
                                    event.getSource().extend(WellKnownPathTypes.Event, event.getId().toString())
                                            .toString())
                            .setActionValue(success ? "SUCCESS" : "FAILURE")
                            .setActor(notificationContext.getUser().getPath().toString())
                            .setActorHost(profileName)
                            .setOriginatingContext(ApplicationScope.GATEWAY)
                            .setOriginatingSystem("Alarming")
                            .setStatusCode(success ? DataQuality.GOOD_DATA.getIntValue() : 0)
                            .setTimestamp(new Date())
                            .build();
                    p.audit(r);
                }
            } catch (Exception e) {
                log.error("Error auditing event.", e);
            }
        }
    }

    private String evaluateStringExpression(NotificationContext notificationContext,
                                            BasicNotificationProfileProperty property) {
        Parser parser = new StringParser();

        FallbackPropertyResolver resolver = new FallbackPropertyResolver(
                context.getAlarmManager().getPropertyResolver());

        FormattedExpressionParseContext parseContext = new FormattedExpressionParseContext(
                new AlarmEventCollectionExpressionParseContext(resolver, notificationContext.getAlarmEvents()));

        String expressionString = null;

        if (property.equals(NtfyProperties.MESSAGE)) {
            String customMessage = notificationContext.getAlarmEvents().get(0).get(NtfyProperties.CUSTOM_MESSAGE);
            boolean isThrottled = notificationContext.getAlarmEvents().size() > 1;

            if (isThrottled || StringUtils.isBlank(customMessage)) {
                expressionString = isThrottled ? notificationContext.getOrDefault(NtfyProperties.THROTTLED_MESSAGE)
                        : notificationContext.getOrDefault(NtfyProperties.MESSAGE);
            } else {
                expressionString = customMessage;
            }
        } else if (property.equals(NtfyProperties.TITLE)) {
            String customTitle = notificationContext.getAlarmEvents().get(0).get(NtfyProperties.CUSTOM_TITLE);
            if (StringUtils.isBlank(customTitle)) {
                expressionString = notificationContext.getOrDefault(NtfyProperties.TITLE);
            } else {
                expressionString = customTitle;
            }
        } else if (property.equals(NtfyProperties.TAGS)) {
            String customTags = notificationContext.getAlarmEvents().get(0).get(NtfyProperties.CUSTOM_TAGS);
            if (StringUtils.isBlank(customTags)) {
                expressionString = notificationContext.getOrDefault(NtfyProperties.TAGS);
            } else {
                expressionString = customTags;
            }
        } else if (property.equals(NtfyProperties.PRIORITY)) {
            String customPriority = notificationContext.getAlarmEvents().get(0).get(NtfyProperties.CUSTOM_PRIORITY);
            if (StringUtils.isBlank(customPriority)) {
                expressionString = notificationContext.getOrDefault(NtfyProperties.PRIORITY);
            } else {
                expressionString = customPriority;
            }
        } else if (property.equals(NtfyProperties.CLICK_ACTION)) {
            String customClick = notificationContext.getAlarmEvents().get(0).get(NtfyProperties.CUSTOM_CLICK);
            if (StringUtils.isBlank(customClick)) {
                expressionString = notificationContext.getOrDefault(NtfyProperties.CLICK_ACTION);
            } else {
                expressionString = customClick;
            }
        } else if (property.equals(NtfyProperties.ATTACH)) {
            String customAttach = notificationContext.getAlarmEvents().get(0).get(NtfyProperties.CUSTOM_ATTACH);
            if (StringUtils.isBlank(customAttach)) {
                expressionString = notificationContext.getOrDefault(NtfyProperties.ATTACH);
            } else {
                expressionString = customAttach;
            }
        } else if (property.equals(NtfyProperties.ACTIONS)) {
            String customActions = notificationContext.getAlarmEvents().get(0).get(NtfyProperties.CUSTOM_ACTIONS);
            if (StringUtils.isBlank(customActions)) {
                expressionString = notificationContext.getOrDefault(NtfyProperties.ACTIONS);
            } else {
                expressionString = customActions;
            }
        } else if (property.equals(NtfyProperties.ICON)) {
            String customIcon = notificationContext.getAlarmEvents().get(0).get(NtfyProperties.CUSTOM_ICON);
            if (StringUtils.isBlank(customIcon)) {
                expressionString = notificationContext.getOrDefault(NtfyProperties.ICON);
            } else {
                expressionString = customIcon;
            }
        } else {
            expressionString = (String) notificationContext.getOrDefault(property);
        }

        if (expressionString == null) {
            return null;
        }

        String evaluated = expressionString;
        try {
            QualifiedValue value = parser.parse(expressionString, parseContext).execute();
            if (value.getQuality().isGood()) {
                evaluated = TypeUtilities.toString(value.getValue());
            }
        } catch (Exception e) {
            log.errorf("Error parsing expression '%s'.", expressionString, e);
        }

        log.tracef("%s evaluated to '%s'.", property.toString(), evaluated);

        return evaluated;
    }

    private String generateActionsString(NotificationContext notificationContext, String actions) {
        if (!StringUtils.isBlank(ackTopic) && ackSubscriber != null) {
            try {
                String s = NtfyAckSubscriber.AckMessage.toString(
                        notificationContext.getAlarmEvents().get(0).getId().toString(),
                        notificationContext.getUser().get(User.Username));
                String encrypted = ackSubscriber.encrypt(s);
                String ackAction = String.format(
                        "http, Ack Alarm, %s/%s, body=%s, method=POST, clear=true, headers.Cache=no ",
                        serverUrl, ackTopic, encrypted);
                actions = String.format("%s; %s", ackAction, actions);
                if (log.isDebugEnabled()) {
                    log.debugf("Actions - %s", actions);
                }
            } catch (Exception ex) {
                log.error("Error generating actions", ex);
            }
        }
        return actions;
    }
}
