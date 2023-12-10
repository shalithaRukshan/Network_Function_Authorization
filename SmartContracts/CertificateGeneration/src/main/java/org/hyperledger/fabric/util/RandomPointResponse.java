package org.hyperledger.fabric.util;

import java.math.BigInteger;

public class RandomPointResponse {

    public String mnoId;
    public byte[] publicKey;
    public BigInteger ephermeralPrivateKey;

    public byte[] getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(byte[] publicKey) {
        this.publicKey = publicKey;
    }

    public BigInteger getEphermeralPrivateKey() {
        return ephermeralPrivateKey;
    }

    public void setEphermeralPrivateKey(BigInteger ephermeralPrivateKey) {
        this.ephermeralPrivateKey = ephermeralPrivateKey;
    }

    public String getMnoId() {
        return mnoId;
    }

    public void setMnoId(String mnoId) {
        this.mnoId = mnoId;
    }
}
