package com.prodguard.checks.premium.security;

import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

class StubHttpProbe implements HttpProbe {

    private final HttpResponse<Void> response;

    StubHttpProbe(HttpResponse<Void> response) {
        this.response = response;
    }

    @Override
    public HttpResponse<Void> send(HttpRequest request) {
        return response;
    }
}
