package com.prodguard.checks.premium.security;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

class JdkHttpProbe implements HttpProbe {

    private final HttpClient client;

    JdkHttpProbe(HttpClient client) {
        this.client = client;
    }

    @Override
    public HttpResponse<Void> send(HttpRequest request) throws Exception {
        return client.send(request, HttpResponse.BodyHandlers.discarding());
    }
}
