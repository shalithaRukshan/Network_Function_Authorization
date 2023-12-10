package org.hyperledger.fabric.samples.mnodetails;

import com.owlike.genson.annotation.JsonProperty;
import org.hyperledger.fabric.contract.annotation.DataType;
import org.hyperledger.fabric.contract.annotation.Property;

import java.util.Objects;

@DataType()
public class Data {

    @Property()
    private final String type;

    @Property
    private final String key;

    @Property()
    private final String value;

    public String getType() {
        return type;
    }

    public String getValue() {
        return value;
    }

    public String getKey() {
        return key;
    }

    public Data(@JsonProperty("type") final String type, @JsonProperty("key") final String key,
                @JsonProperty("value") final String value) {
        this.type = type;
        this.value = value;
        this.key = key;
    }

    @Override
    public boolean equals(final Object obj) {
        if (this == obj) {
            return true;
        }

        if ((obj == null) || (getClass() != obj.getClass())) {
            return false;
        }

        Data other = (Data) obj;

        return Objects.deepEquals(
                new String[]{getType(), getValue(), getKey()},
                new String[]{other.getType(), other.getValue(), getType(), other.getKey()});
    }

    @Override
    public int hashCode() {
        return Objects.hash(getKey(), getType(), getValue());
    }

    @Override
    public String toString() {
        return this.getClass().getSimpleName() + "@" + Integer.toHexString(hashCode()) +
                " [type=" + type + ", key="
                + key + ", value=" + value + "]";
    }

}
