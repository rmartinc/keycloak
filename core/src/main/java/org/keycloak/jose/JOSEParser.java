package org.keycloak.jose;

import java.io.IOException;

import com.fasterxml.jackson.databind.JsonNode;
import org.keycloak.common.util.Base64Url;
import org.keycloak.jose.jwe.JWE;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.util.JsonSerialization;

/**
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public class JOSEParser {

    /**
     * Parses the jwt string if it is detected as a JWS/JWE input. The detection
     * checks if the header is valid.
     *
     * @param jwt the input string that can be a JWT
     * @return a {@link JOSE} or null
     */
    public static JOSE parseIfJWT(String jwt) {
        JsonNode header = parseHeader(jwt);
        if (header == null) {
            return null;
        }

        return createJose(header, jwt);
    }

    /**
     * Parses the given encoded {@code jwt} and returns either a {@link JWSInput} or {@link JWE}
     * depending on the JOSE header configuration.
     *
     * @param jwt the encoded JWT
     * @return a {@link JOSE}
     */
    public static JOSE parse(String jwt) {
        JsonNode header = parseHeader(jwt);
        if (header == null) {
            throw new RuntimeException("Could not infer header from JWT");
        }

        return createJose(header, jwt);
    }

    private static JsonNode parseHeader(String jwt) {
        String[] parts = jwt.split("\\.", -1);

        if (parts.length != 3 && parts.length != 5) {
            return null;
        }

        try {
            JsonNode header = JsonSerialization.readValue(Base64Url.decode(parts[0]), JsonNode.class);
            if (!header.isObject() || !header.has("alg") || (header.has("enc") && parts.length != 5) || (!header.has("enc") && parts.length != 3)) {
                return null;
            }
            return header;
        } catch (IOException cause) {
            return null;
        }
    }

    private static JOSE createJose(JsonNode header, String jwt) {
        if (header.has("enc")) {
            return new JWE(jwt);
        }

        try {
            return new JWSInput(jwt);
        } catch (JWSInputException cause) {
            throw new RuntimeException("Failed to build JWS", cause);
        }
    }
}
