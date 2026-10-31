
package com.frugal.security;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class HmacValidationTest {

    private static final String SECRET =
            "local-development-secret-key";

    private static final String BODY =
            "{\"status\":\"APPROVED\",\"amount\":500}";

    @Test
    void shouldGenerateValidHmacSha512() {

        String mac = HmacSecurity.generateMac(
                BODY,
                1793430000123456L,
                "salt-sequence-001",
                SECRET
        );

        assertNotNull(mac);
        assertEquals(128, mac.length());
        assertTrue(mac.matches("[0-9a-f]{128}"));

        System.out.println(
                "[PASS] HMAC-SHA512 generated successfully"
        );
    }

    @Test
    void shouldVerifyCorrectMac() {

        String mac = HmacSecurity.generateMac(
                BODY,
                1793430000123456L,
                "salt-sequence-001",
                SECRET
        );

        assertTrue(HmacSecurity.verifyMac(mac, mac));

        System.out.println("[PASS] Valid MAC verified");
    }

    @Test
    void shouldRejectTamperedMac() {

        String originalMac = HmacSecurity.generateMac(
                BODY,
                1793430000123456L,
                "salt-sequence-001",
                SECRET
        );

        String tamperedMac =
                "0" + originalMac.substring(1);

        assertFalse(
                HmacSecurity.verifyMac(tamperedMac, originalMac)
        );

        System.out.println("[PASS] Tampered MAC rejected");
    }

    @Test
    void shouldRejectDifferentPayload() {

        String originalMac = HmacSecurity.generateMac(
                BODY,
                1793430000123456L,
                "salt-sequence-001",
                SECRET
        );

        String changedMac = HmacSecurity.generateMac(
                "{\"status\":\"REJECTED\",\"amount\":500}",
                1793430000123456L,
                "salt-sequence-001",
                SECRET
        );

        assertFalse(
                HmacSecurity.verifyMac(changedMac, originalMac)
        );

        System.out.println("[PASS] Different payload detected");
    }
}
