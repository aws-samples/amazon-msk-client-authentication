package com.amazonaws.msk.samples;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

class Util {

    private static final Logger logger = LogManager.getLogger(AuthMSK.class);

    static void writePEMFile(String fileLocation, byte [] pem) throws IOException {
        try (FileOutputStream file = new FileOutputStream(fileLocation)) {
            file.write(pem);
        } catch (FileNotFoundException e) {
            logger.error(String.format("Nonexistent path %s provided for PEM file path. \n", fileLocation));
            throw e;
        }
    }

    static ByteBuffer stringToByteBuffer(final String string) {
        if (Objects.isNull(string)) {
            return null;
        }
        byte[] bytes = string.getBytes(StandardCharsets.UTF_8);
        return ByteBuffer.wrap(bytes);
    }
}
