/*
 * Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.shindig.wso2.ext.impl;

import com.google.inject.Inject;
import com.google.inject.name.Named;
import org.apache.shindig.gadgets.http.HttpRequest;
import org.apache.shindig.wso2.ext.Whitelist;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.utils.CarbonUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;
import java.util.regex.Pattern;

/**
 * Default implementation of {@link Whitelist} interface.
 * Populate the whitelist URI regex patterns list by reading the carbon hostname and configured whitelist in
 * shindig.properties file. To validate a given URI, iterate the regex list and matches.
 */
public class WhitelistImpl implements Whitelist {

    private static final Logger log = Logger.getLogger(WhitelistImpl.class.getName());
    private List<Pattern> whiteListedURIRegexList = new ArrayList<Pattern>();

    public WhitelistImpl() {

        // Add carbon hostname URI to the list. This will be removed if whitelist URLs are configured
        // in shindig.properties file.
        ServerConfiguration serverConfig = CarbonUtils.getServerConfiguration();
        String carbonHostname = serverConfig.getFirstProperty("HostName");
        String url = "https://" + carbonHostname + "/portal";
        addURIRegexToWhiteList(url);
        log.info("URL: " + url + " added to the whitelisted backend URI list.");
    }

    public boolean isWhitelisted(HttpRequest request) {

        if (whiteListedURIRegexList.isEmpty()) {
            return true;
        }

        for (Pattern pattern : whiteListedURIRegexList) {
            if (isMatch(request, pattern)) {
                return true;
            }
        }
        log.warning("Potential External Service Interaction (DNS) attack thwarted. Unauthorized URI: " +
                request.getUri().toString() + " detected in shindig web app request parameters.");
        return false;
    }

    /**
     * Checks whether the given request matches with the whitelisted URI regex patterns.
     *
     * @param request Http Request needed to be authorised.
     * @param pattern Whitelist URI regex pattern to be matched.
     * @return True if matched, false otherwise.
     */
    private boolean isMatch(HttpRequest request, Pattern pattern) {

        String requestedUri = request.getUri().toString();
        return pattern.matcher(requestedUri).matches();
    }

    @Inject(optional = true)
    public void setWhitelistedUrl(@Named("wso2.shindig.proxy.whitelist") String whitelistUrlList) {

        if (whitelistUrlList != null && !whitelistUrlList.isEmpty()) {
            // Reset whiteListedURIRegexList to remove added URLs by default.
            whiteListedURIRegexList = new ArrayList<Pattern>();
            String[] parts = whitelistUrlList.split(",");
            for (String uri: parts) {
                addURIRegexToWhiteList(uri);
            }
        }
    }

    /**
     * Add suitable regex patterns of the provided URI to the whitelist URI regex list.
     *
     * @param uri URI to be whitelisted.
     */
    private void addURIRegexToWhiteList(String uri) {

        String regex;
        if (uri.matches("^.*:[0-9]{4}.*$")) {
            regex = uri.replaceAll("/", "\\/");
        } else {
            String[] uriComponents = uri.split("/");
            regex = "^(" + uriComponents[0] + "\\/\\/" + uriComponents[2] + "):*[0-9]{0,4}(\\/" +
                    uriComponents[3] + ").*$";
        }
        whiteListedURIRegexList.add(Pattern.compile(regex));
    }
}
