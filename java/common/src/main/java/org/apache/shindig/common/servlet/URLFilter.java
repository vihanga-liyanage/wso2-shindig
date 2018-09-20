/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.shindig.common.servlet;

import java.io.BufferedReader;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
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
    private static final String ALLOWED_URLS_PARAM_NAME = "allowedUrls";
    private static Logger log = Logger.getLogger(URLFilter.class.getName());

    private List allowedURLs;

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

            if (!isInvalidHostPresent(URLDecoder.decode(httpRequest.getQueryString(), StandardCharsets.UTF_8.name()))) {
                chain.doFilter(httpRequest, response);
            } else {
                HttpServletResponse httpResponse = (HttpServletResponse) response;
                httpResponse.sendError(HttpServletResponse.SC_FORBIDDEN, "Unauthorized query parameter detected!");
            }
        }
    }

    private boolean handlePOSTRequest(MultiReadHttpServletRequest multiReadRequest) {

        StringBuilder stringBuffer = new StringBuilder();
        String line;
        try {
            BufferedReader reader = multiReadRequest.getReader();
            while ((line = reader.readLine()) != null) {
                stringBuffer.append(line);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return !isInvalidHostPresent(stringBuffer.toString());
    }

    private boolean isInvalidHostPresent(String text) {

        Pattern pattern = Pattern.compile(URL_REGEX);
        Matcher matcher = pattern.matcher(text);

        while (matcher.find()) {
            String match = matcher.group();
            try {
                URI uri = new URI(match);
                if (uri.getHost() != null && !allowedURLs.contains(uri.getHost())) {
                    log.warning("Potential External Service Interaction (DNS) attack thwarted. Unauthorized " +
                            "host name: " + uri.getHost() + " detected in shindig web app request parameters.");
                    return true;
                }
            } catch (URISyntaxException e) {
                e.printStackTrace();
            }
        }
        return false;
    }

    public void destroy() {
    }

    public void init(FilterConfig filterConfig) {

        String allowedURLString = filterConfig.getInitParameter(ALLOWED_URLS_PARAM_NAME);
        allowedURLs = (allowedURLString != null) ? Arrays.asList(allowedURLString.split(",")) : new ArrayList();
    }
}
