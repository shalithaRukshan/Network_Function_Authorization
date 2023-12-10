package org.hyperledger.fabric.samples.mnodetails;

import com.owlike.genson.annotation.JsonProperty;
import org.hyperledger.fabric.contract.annotation.DataType;
import org.hyperledger.fabric.contract.annotation.Property;

import java.util.Objects;

@DataType
public class ECQVCertificate {

    @Property()
    private String issuer;

    @Property()
    private String nf;

    @Property()
    private String publicParam;

    @Property()
    private String issuedAt;

    @Property()
    private String expiredAt;

    @Property()
    private String publicKey;

    public String getIssuer() {
        return issuer;
    }

    public String getNf() {
        return nf;
    }

    public String getPublicParam() {
        return publicParam;
    }

    public String getIssuedAt() {
        return issuedAt;
    }

    public String getExpiredAt() {
        return expiredAt;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public ECQVCertificate(@JsonProperty("issuer") final String issuer, @JsonProperty("nf") final String nf,
                           @JsonProperty("publicParam") final String publicParam,
                           @JsonProperty("issuedAt") final String issuedAt,
                           @JsonProperty("expiredAt") final String expiredAt,
                           @JsonProperty("publicKey") final String publicKey) {
        this.issuer = issuer;
        this.nf = nf;
        this.publicParam = publicParam;
        this.issuedAt = issuedAt;
        this.expiredAt = expiredAt;
        this.publicKey = publicKey;
    }

    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }

        if ((obj == null) || (getClass() != obj.getClass())) {
            return false;
        }

        ECQVCertificate other = (ECQVCertificate) obj;

        return Objects.deepEquals(
                new String[]{getIssuer(), getNf(), getIssuedAt(), getExpiredAt(), getPublicParam(), getPublicKey()},
                new String[]{other.getIssuer(), other.getNf(), other.getIssuedAt(), other.getExpiredAt(), other.getPublicParam(), other.getPublicKey()});
    }

    @Override
    public int hashCode() {
        return Objects.hash(getIssuer(), getNf(), getIssuedAt(), getExpiredAt(), getPublicParam(), getPublicKey());
    }

    @Override
    public String toString() {
        return this.getClass().getSimpleName() + "@" + Integer.toHexString(hashCode()) + " [issuer=" + issuer + ", nf="
                + nf + ", issuedAT=" + issuedAt + ", expiredAt=" + expiredAt + ", contribution=" + publicParam + ", publicKey=" + publicKey + "]";
    }

}
