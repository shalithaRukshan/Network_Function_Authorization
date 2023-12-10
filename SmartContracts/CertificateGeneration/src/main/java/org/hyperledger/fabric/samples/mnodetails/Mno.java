package org.hyperledger.fabric.samples.mnodetails;

import com.owlike.genson.annotation.JsonProperty;
import org.hyperledger.fabric.contract.annotation.DataType;
import org.hyperledger.fabric.contract.annotation.Property;

import java.util.Objects;

@DataType()
public final class Mno {

    @Property()
    private final String type;

    @Property()
    private final String mnoId;

    @Property()
    private final String mnoName;

    @Property()
    private final String host;

    @Property
    private final int port;

    @Property
    private final byte[] publicKey;

    public String getMnoId() {
        return mnoId;
    }

    public String getType() {
        return type;
    }

    public String getMnoName() {
        return mnoName;
    }

    public String getHost() {
        return host;
    }

    public int getPort() {
        return port;
    }

    public byte[] getPublicKey() {
        return publicKey;
    }

    public Mno(@JsonProperty("mnoId") final String mnoId, @JsonProperty("mnoName") final String mnoName,
               @JsonProperty("host") final String host, @JsonProperty("port") int port,
               @JsonProperty("publicKey") byte[] publicKey) {
        this.mnoId = mnoId;
        this.mnoName = mnoName;
        this.host = host;
        this.port = port;
        this.publicKey = publicKey;
        this.type = "MNO";
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
                new String[]{getMnoId(), getMnoName(), getType(), getHost(), String.valueOf(getPort()), getPublicKey().toString()},
                new String[]{other.getMnoId(), other.getMnoName(), getType(), other.getHost(), String.valueOf(other.getPort()),
                        other.getPublicKey().toString()});
    }

    @Override
    public int hashCode() {
        return Objects.hash(getMnoId(), getMnoName(), getType(), getHost(), getPort(), getPublicKey());
    }

    @Override
    public String toString() {
        return this.getClass().getSimpleName() + "@" + Integer.toHexString(hashCode()) +
                " [mnoId=" + mnoId + ", mnoName="
                + mnoName + ", type=" + type + ", host=" + host + ", port=" + port + ", publickey=" + publicKey + "]";
    }

}
