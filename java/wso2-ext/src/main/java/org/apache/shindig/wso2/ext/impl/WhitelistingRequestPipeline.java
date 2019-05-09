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
import com.google.inject.Provider;
import com.google.inject.Singleton;
import org.apache.shindig.common.Nullable;
import org.apache.shindig.gadgets.GadgetException;
import org.apache.shindig.gadgets.http.DefaultRequestPipeline;
import org.apache.shindig.gadgets.http.HttpCache;
import org.apache.shindig.gadgets.http.HttpFetcher;
import org.apache.shindig.gadgets.http.HttpRequest;
import org.apache.shindig.gadgets.http.HttpResponse;
import org.apache.shindig.gadgets.http.HttpResponseMetadataHelper;
import org.apache.shindig.gadgets.http.InvalidationService;
import org.apache.shindig.gadgets.oauth.OAuthRequest;
import org.apache.shindig.gadgets.oauth2.OAuth2Request;
import org.apache.shindig.gadgets.rewrite.ResponseRewriterList;
import org.apache.shindig.gadgets.rewrite.ResponseRewriterRegistry;
import org.apache.shindig.gadgets.rewrite.RewriterRegistry;
import org.apache.shindig.wso2.ext.Whitelist;

/**
 * Implementation of the whitelisting pipeline.
 */
@Singleton
public class WhitelistingRequestPipeline extends DefaultRequestPipeline {

    @Inject
    private Whitelist whitelist;

    @Inject
    public WhitelistingRequestPipeline(HttpFetcher httpFetcher, HttpCache httpCache,
                                       Provider<OAuthRequest> oauthRequestProvider,
                                       Provider<OAuth2Request> oauth2RequestProvider,
                                       @RewriterRegistry(rewriteFlow = ResponseRewriterList.RewriteFlow.REQUEST_PIPELINE)
                                               ResponseRewriterRegistry responseRewriterRegistry,
                                       InvalidationService invalidationService,
                                       @Nullable HttpResponseMetadataHelper metadataHelper) {

        super(httpFetcher, httpCache, oauthRequestProvider, oauth2RequestProvider, responseRewriterRegistry,
                invalidationService, metadataHelper);
    }


    @Override
    public HttpResponse execute(HttpRequest request) throws GadgetException {

        if (whitelist != null) {
            if (!whitelist.isWhitelisted(request)) {
                return HttpResponse.notFound();
            }
        }
        return super.execute(request);
    }
}
