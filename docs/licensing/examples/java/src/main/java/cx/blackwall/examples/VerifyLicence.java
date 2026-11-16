// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025-2026 Andy Dixon

package cx.blackwall.examples;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

public final class VerifyLicence {
    private static final URI VERIFY_URI = URI.create("https://blackwall.cx/licences/v1/verify");
    private static final String EXPECTED_ISSUER = "https://blackwall.cx";
    private static final int MAX_LICENCE_BYTES = 16 * 1024;
    private static final int MAX_RESPONSE_BYTES = 64 * 1024;
    private static final Pattern DNS_LABEL = Pattern.compile("[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?");

    private VerifyLicence() { }

    public static void main(String[] arguments) {
        try {
            verify(arguments);
        } catch (Exception exception) {
            System.err.println("invalid: " + exception.getMessage());
            System.exit(1);
        }
    }

    private static void verify(String[] arguments) throws Exception {
        if (arguments.length != 3) {
            throw new IllegalArgumentException("usage: VerifyLicence <licence-file> <hostname> <project-uuid>");
        }
        String licence = Files.readString(Path.of(arguments[0]), StandardCharsets.UTF_8).trim();
        if (licence.isEmpty() || licence.getBytes(StandardCharsets.UTF_8).length > MAX_LICENCE_BYTES) {
            throw new IllegalArgumentException("licence file is empty or too large");
        }
        String hostname = normaliseHostname(arguments[1]);
        String projectUuid = arguments[2].toLowerCase(Locale.ROOT);

        ObjectMapper mapper = new ObjectMapper()
                .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
                .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
        byte[] requestBody = mapper.writeValueAsBytes(Map.of(
                "licence", licence,
                "expected_hostname", hostname,
                "project_uuid", projectUuid
        ));
        HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build(); // The default SSL context verifies the certificate and hostname.
        HttpRequest request = HttpRequest.newBuilder(VERIFY_URI)
                .timeout(Duration.ofSeconds(10))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofByteArray(requestBody))
                .build();
        HttpResponse<InputStream> response = client.send(request, HttpResponse.BodyHandlers.ofInputStream());
        if (response.statusCode() != 200) {
            throw new SecurityException("verification service returned HTTP " + response.statusCode());
        }
        byte[] responseBody;
        try (InputStream body = response.body()) {
            responseBody = body.readNBytes(MAX_RESPONSE_BYTES + 1);
        }
        if (responseBody.length > MAX_RESPONSE_BYTES) {
            throw new SecurityException("verification response was too large");
        }
        VerificationResponse result = mapper.readValue(responseBody, VerificationResponse.class);
        if (!result.valid() || !"valid".equals(result.code()) || result.claims() == null) {
            throw new SecurityException("licence rejected: " + result.code());
        }
        Claims claims = result.claims();
        Instant checkedAt = Instant.parse(result.checkedAt());
        Instant now = Instant.now();
        if (Duration.between(checkedAt, now).abs().compareTo(Duration.ofMinutes(5)) > 0
                || claims.version() != 1
                || !EXPECTED_ISSUER.equals(claims.issuer())
                || !"blackwall-licence".equals(claims.audience())
                || !projectUuid.equals(claims.projectUuid())
                || !claims.hostnames().contains(hostname)
                || now.plusSeconds(120).getEpochSecond() < claims.notBefore()
                || now.minusSeconds(120).getEpochSecond() > claims.expiresAt()) {
            throw new SecurityException("verified response did not match the local policy");
        }
        System.out.println("valid licence " + claims.licenceId());
    }

    private static String normaliseHostname(String raw) {
        String host = raw.trim().toLowerCase(Locale.ROOT);
        if (host.endsWith(".")) {
            host = host.substring(0, host.length() - 1);
        }
        if (host.isEmpty() || host.length() > 253 || !StandardCharsets.US_ASCII.newEncoder().canEncode(host)
                || host.indexOf(':') >= 0 || host.matches(".*[*/\\\\@?#%].*")) {
            throw new IllegalArgumentException("example expects an exact ASCII DNS hostname without a port");
        }
        for (String label : host.split("\\.", -1)) {
            if (!DNS_LABEL.matcher(label).matches()) {
                throw new IllegalArgumentException("invalid DNS hostname");
            }
        }
        return host;
    }

    public record VerificationResponse(
            boolean valid,
            String code,
            @JsonProperty("checked_at") String checkedAt,
            Claims claims
    ) { }

    @JsonIgnoreProperties(ignoreUnknown = false)
    public record Claims(
            @JsonProperty("v") int version,
            @JsonProperty("licence_id") String licenceId,
            @JsonProperty("iss") String issuer,
            @JsonProperty("aud") String audience,
            @JsonProperty("project_uuid") String projectUuid,
            Entity entity,
            List<String> hostnames,
            List<String> features,
            @JsonProperty("max_instances") long maxInstances,
            @JsonProperty("iat") long issuedAt,
            @JsonProperty("nbf") long notBefore,
            @JsonProperty("exp") long expiresAt,
            @JsonProperty("kid") String keyId,
            @JsonProperty("status_url") String statusUrl,
            @JsonProperty("online_check_seconds") long onlineCheckSeconds
    ) { }

    @JsonIgnoreProperties(ignoreUnknown = false)
    public record Entity(String type, String name, String reference) { }
}
