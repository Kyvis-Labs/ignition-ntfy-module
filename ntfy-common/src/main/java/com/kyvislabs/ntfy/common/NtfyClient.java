package com.kyvislabs.ntfy.common;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;

import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;

public class NtfyClient {
    private final HttpClient httpClient = HttpClient.newHttpClient();
    private Logger logger = Logger.getLogger("ntfy.client");

    public boolean sendMessage(String serverUrl, String topic, String message, String title, String tags, String priority, String clickAction, String attach, String actions, String icon, String username, String password) {
        
        String ntfyUrl = String.format("%s/%s", serverUrl, topic);
        boolean success = true;
        HttpRequest.Builder builder = HttpRequest.newBuilder();

        builder = builder
                .uri(URI.create(ntfyUrl))
                .header("Content-Type", "application/json")
                .timeout(Duration.ofSeconds(10))
                .POST(HttpRequest.BodyPublishers.ofString(message));

         if (!StringUtils.isBlank(username) && !StringUtils.isBlank(password)){
             String valueToEncode = username + ":" + password;
             builder.header("Authentication", "Basic " + Base64.getEncoder().encodeToString(valueToEncode.getBytes()));
         }

        if (!StringUtils.isBlank(title)) {
            builder.header("Title", title);
        }

        if (!StringUtils.isBlank(tags)) {
            builder.header("Tags", tags);
        }

        if (!StringUtils.isBlank(priority)) {
            builder.header("Priority", priority);
        }

        if (!StringUtils.isBlank(clickAction)) {
            builder.header("Click", clickAction);
        }

        if (!StringUtils.isBlank(attach)) {
            builder.header("Attach", attach);
        }

        if (!StringUtils.isBlank(actions)) {
            String[] parts = StringUtils.split(actions,";");
            if (parts.length > 3){
                parts = Arrays.copyOfRange(parts,0,3);
                actions = StringUtils.join(parts, ";");
            }
            builder.header("Action", actions);
        }

        if (!StringUtils.isBlank(icon)) {
            builder.header("Icon", icon);
        }

        final HttpRequest request = builder.build();
        try {

            final HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (!(response.statusCode() >= 200 && response.statusCode() <= 399)) {
                logger.error("Error sending notification: status code=" + response.statusCode() + ", response=" + response.body());
            }
        } catch (IOException e) {
            logger.error("Unable to send notification", e);
            success = false;
        } catch (InterruptedException e) {
            logger.error("Unable to send notification", e);
            success = false;
        }

        return success;

    }

}
