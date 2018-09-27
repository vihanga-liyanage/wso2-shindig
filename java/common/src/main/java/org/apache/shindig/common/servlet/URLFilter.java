/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.shindig.common.servlet;

import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.utils.CarbonUtils;

import java.io.BufferedReader;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * A filter that checks for external URLs in shindig request parameters.
 */
public class URLFilter implements Filter {

    private static final String URL_REGEX = "https?://[-a-zA-Z0-9+&@#%?=~_|!:,.;]*";
    private static final String ALLOWED_HOST_NAMES_PARAM = "allowedHostNames";
    private static Logger log = Logger.getLogger(URLFilter.class.getName());

    private List<String> allowedHostNames;

    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;

        if (httpRequest.getMethod().equalsIgnoreCase("POST")) {

            // MultiReadHttpServletRequest is used to read request data more than once.
            MultiReadHttpServletRequest multiReadRequest = new MultiReadHttpServletRequest(httpRequest);

            if (handlePOSTRequest(multiReadRequest)) {
                chain.doFilter(multiReadRequest, response);
            } else {
                HttpServletResponse httpResponse = (HttpServletResponse) response;
                httpResponse.sendError(HttpServletResponse.SC_FORBIDDEN, "Unauthorized body parameter detected!");
            }

        } else if (httpRequest.getMethod().equalsIgnoreCase("GET")) {

            if (!isInvalidHostNamePresent(URLDecoder.decode(httpRequest.getQueryString(), "UTF-8"))) {
                chain.doFilter(httpRequest, response);
            } else {
                HttpServletResponse httpResponse = (HttpServletResponse) response;
                httpResponse.sendError(HttpServletResponse.SC_FORBIDDEN, "Unauthorized query parameter detected!");
            }
        }
    }

    private boolean handlePOSTRequest(MultiReadHttpServletRequest multiReadRequest) throws ServletException {

        StringBuilder stringBuffer = new StringBuilder();
        String line;
        try {
            BufferedReader reader = multiReadRequest.getReader();
            while ((line = reader.readLine()) != null) {
                stringBuffer.append(line);
            }
        } catch (IOException e) {
            throw new ServletException("Error occurred while reading request body in shindig URL filter.", e);
        }

        return !isInvalidHostNamePresent(stringBuffer.toString());
    }

    private boolean isInvalidHostNamePresent(String text) throws ServletException {

        Pattern pattern = Pattern.compile(URL_REGEX);
        Matcher matcher = pattern.matcher(text);

        while (matcher.find()) {
            String match = matcher.group();
            try {
                URI uri = new URI(match);
                if (uri.getHost() != null && !allowedHostNames.contains(uri.getHost())) {
                    log.warning("Potential External Service Interaction (DNS) attack thwarted. Unauthorized " +
                            "host name: " + uri.getHost() + " detected in shindig web app request parameters.");
                    return true;
                }
            } catch (URISyntaxException e) {
                throw new ServletException("Error occurred while validating request parameters in shindig " +
                        "URL filter.", e);
            }
        }
        return false;
    }

    public void destroy() {
    }

    public void init(FilterConfig filterConfig) {

        ServerConfiguration serverConfig = CarbonUtils.getServerConfiguration();

        StringBuffer allowedHostNamesBuffer = new StringBuffer();
        // Reading hostname from carbon.xml file.
        appendParam(allowedHostNamesBuffer, serverConfig.getFirstProperty("HostName"));
        // Reading allowed host names passed as filter init params.
        appendParam(allowedHostNamesBuffer, filterConfig.getInitParameter(ALLOWED_HOST_NAMES_PARAM));
        // Reading allowed host names passed as JVM system properties.
        appendParam(allowedHostNamesBuffer, System.getProperty(ALLOWED_HOST_NAMES_PARAM));

        allowedHostNames = Arrays.asList(allowedHostNamesBuffer.toString().trim().split("\\s*,\\s*"));
    }

    private void appendParam(StringBuffer buffer, String param) {

        if (param != null) {
            if (buffer.length() > 0) {
                buffer.append(", ");
            }
            buffer.append(param);
        }
    }
}
