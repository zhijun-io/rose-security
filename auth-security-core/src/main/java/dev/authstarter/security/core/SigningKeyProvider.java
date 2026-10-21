package dev.authstarter.security.core;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Collection;

/** Supplies externally managed signing material. Implementations should delegate private-key operations to a KMS when available. */
public interface SigningKeyProvider {

    SigningKey currentSigningKey();

    Collection<VerificationKey> verificationKeys();

    record SigningKey(String keyId, PrivateKey privateKey, PublicKey publicKey) {
        public SigningKey {
            if (keyId == null || keyId.isBlank() || privateKey == null || publicKey == null) {
                throw new IllegalArgumentException("A key id and both key handles are required");
            }
        }
    }

    record VerificationKey(String keyId, PublicKey publicKey) {
        public VerificationKey {
            if (keyId == null || keyId.isBlank() || publicKey == null) {
                throw new IllegalArgumentException("A key id and public key are required");
            }
        }
    }
}
