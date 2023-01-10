package com.kyvislabs.ntfy.gateway.profile;

import com.google.common.base.Predicate;
import com.google.common.collect.Collections2;
import com.google.common.collect.Lists;
import com.inductiveautomation.ignition.alarming.common.notification.BasicNotificationProfileProperty;
import com.inductiveautomation.ignition.alarming.common.notification.NotificationProfileProperty;
import com.inductiveautomation.ignition.alarming.notification.AlarmNotificationProfile;
import com.inductiveautomation.ignition.alarming.notification.AlarmNotificationProfileRecord;
import com.inductiveautomation.ignition.alarming.notification.NotificationContext;
import com.inductiveautomation.ignition.common.TypeUtilities;
import com.inductiveautomation.ignition.common.WellKnownPathTypes;
import com.inductiveautomation.ignition.common.alarming.AlarmEvent;
import com.inductiveautomation.ignition.common.config.FallbackPropertyResolver;
import com.inductiveautomation.ignition.common.expressions.parsing.Parser;
import com.inductiveautomation.ignition.common.expressions.parsing.StringParser;
import com.inductiveautomation.ignition.common.model.ApplicationScope;
import com.inductiveautomation.ignition.common.model.values.QualifiedValue;
import com.inductiveautomation.ignition.common.sqltags.model.types.DataQuality;
import com.inductiveautomation.ignition.common.user.ContactInfo;
import com.inductiveautomation.ignition.common.user.ContactType;
import com.inductiveautomation.ignition.common.user.User;
import com.inductiveautomation.ignition.gateway.audit.AuditProfile;
import com.inductiveautomation.ignition.gateway.audit.AuditRecord;
import com.inductiveautomation.ignition.gateway.audit.AuditRecordBuilder;
import com.inductiveautomation.ignition.gateway.expressions.AlarmEventCollectionExpressionParseContext;
import com.inductiveautomation.ignition.gateway.expressions.FormattedExpressionParseContext;
import com.inductiveautomation.ignition.gateway.localdb.persistence.PersistenceSession;
import com.inductiveautomation.ignition.gateway.model.GatewayContext;
import com.inductiveautomation.ignition.gateway.model.ProfileStatus;
import com.kyvislabs.ntfy.common.NtfyClient;

import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;
import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;


public class NtfyNotificationProfile implements AlarmNotificationProfile {

    private final GatewayContext context;
    private String auditProfileName, profileName, serverUrl, ackTopic, username, password;
    private final ScheduledExecutorService executor;
    private volatile ProfileStatus profileStatus = ProfileStatus.UNKNOWN;
    private Logger logger;
    private NtfyAckSubscriber ackSubscriber;
    private NtfyClient ntfyClient = new NtfyClient();

    public NtfyNotificationProfile(final GatewayContext context,
            final AlarmNotificationProfileRecord profileRecord,
            final NtfyNotificationProfileSettings settingsRecord) {
        this.context = context;
        this.executor = Executors.newSingleThreadScheduledExecutor();
        this.profileName = profileRecord.getName();
        this.serverUrl = settingsRecord.getServerUrl();
        this.ackTopic = settingsRecord.getAckTopic();
        this.username = settingsRecord.getUsername();
        this.password = settingsRecord.getPassword();
        this.logger = Logger.getLogger(String.format("Ntfy.%s.Profile", this.profileName));

        try (PersistenceSession session = context.getPersistenceInterface().getSession(settingsRecord.getDataSet())) {
            auditProfileName = settingsRecord.getAuditProfileName();
        } catch (Exception e) {
            logger.error("Error retrieving notification profile details.", e);
        }
    }

    @Override
    public String getName() {
        return profileName;
    }

    @Override
    public Collection<NotificationProfileProperty<?>> getProperties() {
        return Lists.newArrayList(
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
        return Lists.newArrayList(NtfyNotificationProfileType.NTFY);
    }

    @Override
    public void onShutdown() {
        executor.shutdown();
        ackSubscriber.getExecutor().shutdown();
    }

    @Override
    public void onStartup() {
        profileStatus = ProfileStatus.RUNNING;
        this.ackSubscriber = new NtfyAckSubscriber(context, profileName, serverUrl, ackTopic); 
    }

    @Override
    public void sendNotification(final NotificationContext notificationContext) {
        executor.execute(() -> {

            Collection<ContactInfo> contactInfos =
                    Collections2.filter(notificationContext.getUser().getContactInfo(), new IsNtfyContactInfo());
            notificationContext.forEach(s -> System.out.print(s));
            String message = evaluateStringExpression(notificationContext, NtfyProperties.MESSAGE);
            String title = evaluateStringExpression(notificationContext, NtfyProperties.TITLE);
            String priority = evaluateStringExpression(notificationContext,NtfyProperties.PRIORITY);
            String tags = evaluateStringExpression(notificationContext,NtfyProperties.TAGS);
            String clickAction = evaluateStringExpression(notificationContext,NtfyProperties.CLICK_ACTION);
            String attach = evaluateStringExpression(notificationContext,NtfyProperties.ATTACH);
            String actions = evaluateStringExpression(notificationContext,NtfyProperties.ACTIONS);
            String icon = evaluateStringExpression(notificationContext,NtfyProperties.ICON);
            boolean testMode = notificationContext.getOrDefault(NtfyProperties.TEST_MODE);

            actions = generateActionsString(notificationContext, actions);

            boolean success = true;
            if (testMode) {
                logger.info(
                        String.format("THIS PROFILE IS RUNNING IN TEST MODE. The following WOULD have been sent:\nMessage: %s, Title=%s",
                                message, title)
                );

                notificationContext.notificationDone();
                return;
            }
            for (ContactInfo contactInfo : contactInfos) {
                String topic = contactInfo.getValue();

                logger.debug(
                        String.format("Attempting to send an alarm notification to topic %s via %s [message=%s, title=%s]",
                                notificationContext.getUser(),
                                topic,
                                message,
                                title)
                );

                success = ntfyClient.sendMessage(serverUrl, topic, message, title, tags, priority, clickAction, attach, actions, icon, username, password);
                audit(success, String.format("Ntfy message to topic %s", topic), notificationContext);
            }


            notificationContext.notificationDone();
        });
    }

    private void audit(boolean success, String eventDesc, NotificationContext notificationContext) {
        logger.debug(String.format("auditing to %s", auditProfileName));
        if (!StringUtils.isBlank(auditProfileName)) {
            try {
                AuditProfile p = context.getAuditManager().getProfile(auditProfileName);
                if (p == null) {
                    return;
                }
                List<AlarmEvent> alarmEvents = notificationContext.getAlarmEvents();
                for (AlarmEvent event : alarmEvents) {
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
                logger.error("Error auditing event.", e);
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
            logger.error(String.format("Error parsing expression '%s'.", expressionString, e));
        }

        logger.trace(String.format("%s evaluated to '%s'.", property.toString(), evaluated));

        return evaluated;
    }

    /**
     * A {@link Predicate} that returns true if a {@link ContactInfo}'s
     * {@link ContactType} is Console.
     */
    private static class IsNtfyContactInfo implements Predicate<ContactInfo> {
        @Override
        public boolean apply(ContactInfo contactInfo) {
            return NtfyNotificationProfileType.NTFY.getContactType().equals(contactInfo.getContactType());
        }
    }

    private String generateActionsString(NotificationContext notificationContext, String actions){
        if (!StringUtils.isBlank(ackTopic)){
            try {
                String s = NtfyAckSubscriber.AckMessage.toString(notificationContext.getAlarmEvents().get(0).getId().toString(),notificationContext.getUser().get(User.Username));
                String encrypted = ackSubscriber.encrypt(s);
                String ackAction = String.format("http, Ack Alarm, %s/%s, body=%s, method=POST, clear=true, headers.Cache=no ", serverUrl, ackTopic, encrypted);
                actions = String.format("%s; %s",ackAction,actions);
                if (logger.isDebugEnabled()){
                    logger.debug(String.format("Actions - %s",actions));
                }
            }  catch (Exception ex) {
                logger.error("Error",ex);
            }
        }
        return actions;
    }
}
