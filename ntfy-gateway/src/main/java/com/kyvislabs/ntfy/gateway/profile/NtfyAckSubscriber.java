package com.kyvislabs.ntfy.gateway.profile;

import java.io.*;
import java.lang.String;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import org.apache.log4j.Logger;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.inductiveautomation.ignition.common.QualifiedPath;
import com.inductiveautomation.ignition.common.alarming.EventData;
import com.inductiveautomation.ignition.common.alarming.config.CommonAlarmProperties;
import com.inductiveautomation.ignition.common.config.PropertySet;
import com.inductiveautomation.ignition.common.config.PropertySetBuilder;
import com.inductiveautomation.ignition.gateway.model.GatewayContext;

public class NtfyAckSubscriber {

    private GatewayContext context;
    private String serverUrl;
    private String ackTopic;
    private ScheduledExecutorService executor;
    private Logger logger;
    private int reconnectTime = 250;
    ObjectMapper mapper = new ObjectMapper();
    KeyGenerator keyGenerator;
    private SecretKey key;
    private Cipher encryptionCipher;

    public NtfyAckSubscriber(GatewayContext context, String profileName, String serverUrl, String topic) {

        this.context = context;
        this.serverUrl = serverUrl;
        this.ackTopic = topic;
        this.logger = Logger.getLogger(String.format("Ntfy.%s.AckSubscriber", profileName));

        try {
            keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(256);
            key = keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            logger.error("Error creating key generator.", e);
        }

        String streamUrl = String.format("%s/%s/json",serverUrl,ackTopic);
        this.executor = Executors.newSingleThreadScheduledExecutor();
        executor.execute(() -> {
            while (!executor.isShutdown()){
                String charset = "UTF-8";
                HttpURLConnection connection = null;
                InputStream inputStream = null;

                try {
                    connection = getConnection(streamUrl);

                    inputStream = connection.getInputStream();
                    int responseCode = connection.getResponseCode();
                    reconnectTime = 250;

                    if (responseCode >= 200 && responseCode <= 299) {

                        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream, charset));
                String line = reader.readLine();

                        while(line != null){
                            ackAlarm(line);
                            logger.trace(line);
                            line = reader.readLine();
                        }
                    } else {
                        handleNonSuccessResponse(connection);
                    }
                } catch (Exception e) {
                    handleNonSuccessResponse(connection);
                } finally {
                    if (inputStream != null) {
                        try {
                            inputStream.close();
                        } catch (IOException e) {
                            logger.debug("Error closing stream",e);
                        }
                    }
                }
                logger.debug(String.format("Sleeping for %s ms",reconnectTime));
                try {
                    Thread.sleep(reconnectTime);
                } catch (InterruptedException e) {
                }

                if (reconnectTime < 256000) {
                    NtfyAckSubscriber.this.reconnectTime = reconnectTime*2;
                }
            }
        });
    }

    private void handleNonSuccessResponse(HttpURLConnection connection) {
        
        int responseCode;
        try {
            responseCode = connection.getResponseCode();
            String responseMessage = connection.getResponseMessage();
            logger.error("Non-success response: " + responseCode + " -- " + responseMessage);
        } catch (IOException e) {
            logger.error("Error connecting to server",e);
        }

    }

    private HttpURLConnection getConnection(String urlString)
            throws IOException {
        URL url = new URL(urlString);

        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setReadTimeout(1000 * 60 * 60);
        connection.setConnectTimeout(1000 * 10);

        return connection;
    }

    private static String createAuthHeader(String username, String password) throws UnsupportedEncodingException {
        String authToken = username + ":" + password;
        return "Basic " + Base64.getEncoder().encode(authToken.getBytes());
    }

    public ScheduledExecutorService getExecutor() {
        return this.executor;
    }

    private void ackAlarm(String text){
        final var json = text.toString();
        try {
            Message msg = mapper.readValue(json, Message.class);
            if ("message".equals(msg.event)) {
                String unencrypted = decrypt(msg.message);
                AckMessage ack = AckMessage.fromNtfyMessage(unencrypted);
                List<UUID> uuidToAck = new ArrayList<>();
                uuidToAck.add(UUID.fromString(ack.event));

                final var ackUser = new QualifiedPath.Builder().setProvider("default").setUser(ack.user).build();
                PropertySet eventData = new PropertySetBuilder().set(CommonAlarmProperties.AckUser, ackUser).build();
                context.getAlarmManager().acknowledgeBulk(uuidToAck,new EventData(eventData));
            }

        } catch (JsonProcessingException e) {
            logger.error("Message not valid",e);
        } catch (Exception e){
            logger.error("Something is wrong",e);
        }
    }

    public String encrypt(String data) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        byte[] dataInBytes = data.getBytes();
        encryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
        encryptionCipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedBytes = encryptionCipher.doFinal(dataInBytes);
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    private String decrypt(String encryptedData) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException{
        byte[] dataInBytes = Base64.getDecoder().decode(encryptedData);
        Cipher decryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, encryptionCipher.getIV());
        decryptionCipher.init(Cipher.DECRYPT_MODE, key, spec);
        byte[] decryptedBytes = decryptionCipher.doFinal(dataInBytes);
        return new String(decryptedBytes);
    }

    @JsonAutoDetect(fieldVisibility = Visibility.ANY)
    private static class Message {
        String id;
        Long time;
        String event;
        String topic;
        String title;
        String message;

        public Message(){
        }
    }

    @JsonAutoDetect(fieldVisibility = Visibility.ANY)
    public static class AckMessage {
        String event, user;
        static String delimiter = ";";
        public static AckMessage fromNtfyMessage(String msg){
            final String[] parts = msg.split(";");
            return new AckMessage(parts[0],parts[1]);

        }
        public AckMessage(String event,String user){
            this.event = event;
            this.user = user;
        }

        public static String toString(String event,String user){
            return String.format("%s%s%s", event, delimiter, user);
        }

    }
}
