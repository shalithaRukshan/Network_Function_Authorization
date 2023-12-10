package org.hyperledger.fabric.samples.mnodetails;

import com.owlike.genson.annotation.JsonProperty;
import org.hyperledger.fabric.contract.annotation.DataType;
import org.hyperledger.fabric.contract.annotation.Property;

import java.util.Objects;

@DataType
public final class Certificate {

    @Property()
    private final String certId;

    @Property()
    private final String certHash;

    @Property()
    private final boolean isRevoked;

    @Property()
    private final String certificate;

    public String getCertId() {
        return certId;
    }

    public String getCertHash() {
        return certHash;
    }

    public String getCertificate() {
        return certificate;
    }

    public Certificate(@JsonProperty("certId") final String certId, @JsonProperty("certHash") final String certHash,
                       @JsonProperty("certificate") final String certificate,
                       @JsonProperty("isRevoked") final boolean isRevoked) {
        this.certId = certId;
        this.certHash = certHash;
        this.certificate = certificate;
        this.isRevoked = isRevoked;
    }

    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }

        if ((obj == null) || (getClass() != obj.getClass())) {
            return false;
        }

        Mno other = (Mno) obj;

        return Objects.deepEquals(
                new String[]{getCertId(), getCertHash(), getCertificate()},
                new String[]{other.getMnoId(), other.getMnoName(), other.getHost()});
    }

    @Override
    public int hashCode() {
        return Objects.hash(getCertId(), getCertHash(), getCertificate());
    }

    @Override
    public String toString() {
        return this.getClass().getSimpleName() + "@" + Integer.toHexString(hashCode()) + " [mnoId=" + certId + ", mnoName="
                + certHash + ", endpoint=" + certificate + "]";
    }
}
