package org.hyperledger.fabric.util;

import java.io.IOException;
import java.math.BigInteger;

public class ECOperations {


    /**
     * Compute the integer e from H(Certu)
     *
     * @param n             Curve order.
     * @param messageDigest Message digest.
     * @return e value.
     */
    public static BigInteger calculateE(BigInteger n, byte[] messageDigest) {
        // n.bitLength() == ceil(log2(n < 0 ? -n : n+1)
        // we actually want floor(log_2(n)) which is n.bitLength()-1
        int log2n = n.bitLength() - 1;
        int messageBitLength = messageDigest.length * 8;

        if (log2n >= messageBitLength) {
            return new BigInteger(1, messageDigest);
        } else {
            BigInteger trunc = new BigInteger(1, messageDigest);

            trunc = trunc.shiftRight(messageBitLength - log2n);

            return trunc;
        }
    }

    /**
     * Convert an octet string to a {@link BigInteger BigInteger}.
     *
     * @param os the octet string
     * @return The {@link BigInteger BigInteger} value.
     */
    public BigInteger octetStringToInteger(byte[] os) {
        int osLen = os.length;
        byte[] osSigned;

        // Always prepend 0x00 byte to make it positive signed integer
        // (instead of checking the length of 'os' & 'modulus')
        osSigned = new byte[osLen + 1];
        System.arraycopy(os, 0, osSigned, 1, osLen);
        return new BigInteger(osSigned);
    }

    /**
     * Converts the given integer value and the given modulus to an octet string.
     *
     * @param r       Integer value to convert.
     * @param modulus Modulus to convert.
     * @return Octet string representing r and modulus.
     * @throws IOException if r is greater than modulus.
     */
    public byte[] integerToOctetString(BigInteger r, BigInteger modulus) throws IOException {
        byte[] modulusBytes = modulus.toByteArray();
        int modulusLen = modulusBytes.length;
        byte[] rBytes = r.toByteArray();
        int rLen = rBytes.length;
        int rMSB = rBytes[0] & 0xFF;

        if (modulusBytes[0] == 0x00) {
            modulusLen -= 1;
        }

        // for arrays that are more than one byte longer
        if ((rLen == modulusLen + 1 && rMSB != 0x00) || rLen > modulusLen + 1) {
            throw new IOException("Integer value is larger than modulus");
        }

        byte[] rUnsigned = new byte[modulusLen];
        System.arraycopy(rBytes, (rLen > modulusLen) ? (rLen - modulusLen) : 0, rUnsigned,
                (modulusLen > rLen) ? (modulusLen - rLen) : 0, (modulusLen > rLen) ? rLen : modulusLen);

        return rUnsigned;
    }
}
