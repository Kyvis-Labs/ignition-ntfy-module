package com.kyvislabs.ntfy.gateway;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.inductiveautomation.ignition.common.QualifiedPath;
import com.inductiveautomation.ignition.common.alarming.EventData;
import com.inductiveautomation.ignition.common.alarming.config.CommonAlarmProperties;
import com.inductiveautomation.ignition.common.config.PropertySet;
import com.inductiveautomation.ignition.common.config.PropertySetBuilder;

public class NtfyServlet extends HttpServlet {
    private final Logger logger = LoggerFactory.getLogger("Ntfy.Webhook.Servlet");

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        resp.sendError(501, "Not Implemented");
    }

    @Override
    protected void doHead(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        resp.sendError(501, "Not Implemented");
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String response = IOUtils.toString(req.getReader());
        final var eventId = req.getParameter("event");
        final var user = req.getParameter("user");
        List<UUID> uuidToAck = new ArrayList<>();
        uuidToAck.add(UUID.fromString(eventId));

        final var ackUser = new QualifiedPath.Builder().setProvider("default").setUser(user).build();
        PropertySet eventData = new PropertySetBuilder().set(CommonAlarmProperties.AckUser, ackUser).build();
        GatewayHook.gatewayContext.getAlarmManager().acknowledge(uuidToAck,new EventData(eventData));
        logger.debug("Webhook URI: " + req.getRequestURI());
        logger.debug("Webhook response: " + response);

        resp.setHeader("Access-Control-Allow-Origin","*");
        resp.setStatus(HttpServletResponse.SC_OK);
    }

    @Override
    protected void doPut(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        resp.sendError(501, "Not Implemented");
    }

    @Override
    protected void doDelete(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        resp.sendError(501, "Not Implemented");
    }

    @Override
    protected void doOptions(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        resp.sendError(501, "Not Implemented");
    }

    @Override
    protected void doTrace(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        resp.sendError(501, "Not Implemented");
    }
}
