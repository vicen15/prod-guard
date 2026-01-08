package com.prodguard.checks.premium.security;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import javax.net.ssl.SSLSession;

class StubHttpResponse implements HttpResponse<Void> {

    private final int status;
    private final Map<String, List<String>> headers;

    StubHttpResponse(int status, Map<String, List<String>> headers) {
        this.status = status;
        this.headers = headers;
    }

    @Override public int statusCode() { return status; }
    @Override public HttpHeaders headers() { return HttpHeaders.of(headers, (a,b) -> true); }

    @Override
    public Optional<SSLSession> sslSession() {
        return Optional.empty();
    }    
    
    // métodos no usados
    @Override public Void body() { return null; }
    @Override public URI uri() { return null; }
    @Override public HttpClient.Version version() { return null; }
    @Override public Optional<HttpResponse<Void>> previousResponse() { return Optional.empty(); }
    @Override public HttpRequest request() { return null; }
}
