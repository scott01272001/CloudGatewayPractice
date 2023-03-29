package com.scott.cloudgatewaypractice.web.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.extern.log4j.Log4j2;

import java.math.BigInteger;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Enumeration;
import java.util.UUID;

@Log4j2
public class JwtUtil {

    public static final String AUDIENCE_ACCESS = "access";
    public static final String AUDIENCE_REFRESH = "refresh";
    private static final byte[] secret = "dba07706d548".getBytes(StandardCharsets.UTF_8);
    private static final char[] hexArray = "0123456789ABCDEF".toCharArray();
    private static String serverHashId;

    static {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.reset();

            Enumeration<NetworkInterface> nets = NetworkInterface.getNetworkInterfaces();
            while (nets.hasMoreElements()) {
                NetworkInterface net = nets.nextElement();
                if (!net.isLoopback() && net.getHardwareAddress() != null) {
                    String macAddr = bytesToHex(net.getHardwareAddress());
                    if (!macAddr.substring(0, 4).equals("0242")) { // exclude Docker MAC address 02:42:xx:xx:xx:xx
                        digest.update(net.getHardwareAddress());
                    }
                }
            }

            serverHashId = String.format("%064x", new BigInteger(1, digest.digest()));
        } catch (NoSuchAlgorithmException | SocketException e) {
            log.error("Cannot generate server id", e);
            // generate a uuid which invalid after restart
            serverHashId = UUID.randomUUID().toString();
        }
    }

    public static DecodedJWT decodeToken(String token) {
        DecodedJWT jwt = JWT.require(algorithm()).build().verify(token);
        if (serverHashId.equals(jwt.getIssuer())) {
            return jwt;
        }
        throw new JWTVerificationException("Invalid issuer");
    }

    private static Algorithm algorithm() {
        return Algorithm.HMAC512(secret);
    }

    private static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

}
