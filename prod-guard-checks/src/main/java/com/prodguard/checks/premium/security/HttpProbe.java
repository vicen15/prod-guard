package com.prodguard.checks.premium.security;

import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

public interface HttpProbe {
    HttpResponse<Void> send(HttpRequest request) throws Exception;
}
