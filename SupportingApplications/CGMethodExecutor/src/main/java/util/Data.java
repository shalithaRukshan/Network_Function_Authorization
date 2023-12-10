package util;

import com.owlike.genson.annotation.JsonProperty;

import java.util.Objects;

public class Data {

    private final String type;

    private final String key;

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
