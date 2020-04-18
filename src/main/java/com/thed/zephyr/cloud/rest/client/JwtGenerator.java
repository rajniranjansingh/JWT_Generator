package com.thed.zephyr.cloud.rest.client;

import java.net.URI;

public interface JwtGenerator 
{
    String generateJWT(String requestMethod, URI uri, int jwtExpiryWindowSeconds);
}
