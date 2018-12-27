/**
 * Copyright (C) 2015 The Gravitee team (http://gravitee.io)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.gravitee.policy.keychainqueryinjection;

import com.google.gson.JsonParser;
import io.gravitee.common.http.HttpStatusCode;
import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.Request;
import io.gravitee.gateway.api.Response;
import io.gravitee.policy.api.PolicyChain;
import io.gravitee.policy.api.PolicyResult;
import io.gravitee.policy.api.annotations.OnRequest;

import io.gravitee.policy.keychainqueryinjection.configuration.KeychainQueryInjectionPolicyConfiguration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.json.JSONException;

import com.google.gson.JsonObject;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
@SuppressWarnings("unused")
public class KeychainQueryInjectionPolicy {

    private static final Logger LOGGER = LoggerFactory.getLogger(KeychainQueryInjectionPolicy.class);

    static final String KEYCHAIN_STRING = "keychain";
    static final String USER_STRING = "user";
    static final String PASS_STRING = "pass";
    static final String METHOD_STRING = "method";
    static final String QUERYINJECTION = "query";
    static final String[] FILTERED_PROPERTIES = {"appId", "apiId", "gw", "method", "hash"};

    static Map<String, String> params = new HashMap();

    /**
     * Policy configuration
     */
    private final KeychainQueryInjectionPolicyConfiguration keychainQueryInjectionPolicyConfiguration;

    public KeychainQueryInjectionPolicy(KeychainQueryInjectionPolicyConfiguration keychainQueryInjectionPolicyConfiguration) {
        this.keychainQueryInjectionPolicyConfiguration = keychainQueryInjectionPolicyConfiguration;
    }

    @OnRequest
    public void onRequest(Request request, Response response, ExecutionContext executionContext, PolicyChain policyChain) {
        String keychainResponse = (String)executionContext.getAttribute("keychain");

        String requestKeychain = lookForKeychain(executionContext, request);

        KeychainQueryInjectionPolicy.LOGGER.warn(requestKeychain);

        if (requestKeychain == null || requestKeychain.isEmpty()) {
            policyChain.failWith(PolicyResult.failure(
                    HttpStatusCode.FORBIDDEN_403,
                    "Couldn't find keychain data inside context."));
            return;
        }

        try
        {
            String[] filter = FILTERED_PROPERTIES;

//        System.out.println("JSON: " + requestKeychain);
            JsonParser p = new JsonParser();
            buildFilteredList(filter, p.parse(requestKeychain));
            System.out.println("list size: " + params.size());
//        System.out.println(params);


            if(params.size() == 0) {
                policyChain.failWith(PolicyResult.failure(HttpStatusCode.NOT_IMPLEMENTED_501, "Method not supported yet. "));
                return;
            }

            request.uri().concat("?");

            for (Map.Entry<String, String> param : params.entrySet())
            {
                request.uri().concat(param.getKey() + "=" + param.getValue() + "&");
                System.out.println(param.getKey() + "=" + param.getValue());
            }


        }
        catch (JSONException e)
        {
            policyChain.failWith(PolicyResult.failure(HttpStatusCode.FORBIDDEN_403, e.getMessage()));
            return;
        }

        policyChain.doNext(request,response);
    }

    private String lookForKeychain(ExecutionContext executionContext, Request request) {

        Object attrib = executionContext.getAttribute(KEYCHAIN_STRING);
        String keychainResponse = null;

        if(attrib!=null)
            keychainResponse = (String)attrib;

        // clean auth request
//        String authorization = request.headers().getFirst(ATTR_AUTHORIZATION_KEY);
//        if(authorization != null)
//            request.headers().remove(ATTR_AUTHORIZATION_KEY);

        return keychainResponse;
    }

    private static void buildFilteredList(String[] filter, JsonElement jsonElement)
    {

        if (jsonElement.isJsonArray())
        {
            for (JsonElement jsonElement1 : jsonElement.getAsJsonArray())
            {
                buildFilteredList(filter, jsonElement1);
            }
        }
        else
        {
            Set<Map.Entry<String, JsonElement>> entrySet = jsonElement.getAsJsonObject().entrySet();

            if (jsonElement.isJsonObject()) {

                JsonObject elem =  jsonElement.getAsJsonObject();

                for (Map.Entry<String, JsonElement> entry : entrySet)
                {
                    String key = entry.getKey();

                    //if (key1.equals(key)) {
                    if(elem.get("method").toString().replace("\"", "").equals(QUERYINJECTION))
                    {
                        if (!(Arrays.asList(filter).contains(key))) {
                            params.put(key, entry.getValue().toString().replace("\"", ""));
                            System.out.println(key + ":" + entry.getValue().toString().replace("\"", ""));
                        }

                    }


                    //buildFilteredList(filter, entry.getValue());
                }

            }
            else
            {
//                Iterator keys = jsonElement.keys();
//
//                while (keys.hasNext()) {
//                    String key = (String) keys.next();
//                    map.put(key, fromJson(object.get(key)));
//                }

                if(!(Arrays.asList(filter).contains(jsonElement.toString()))) {
                    params.put("single", jsonElement.toString());
                }

            }

        }

    }

}
