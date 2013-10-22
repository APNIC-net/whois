package net.ripe.db.whois.common.support;

import com.Ostermiller.util.LineEnds;
import org.apache.commons.compress.archivers.zip.ZipArchiveEntry;
import org.apache.commons.compress.archivers.zip.ZipArchiveOutputStream;
import org.apache.commons.io.IOUtils;
import org.apache.commons.io.output.ByteArrayOutputStream;
import org.apache.commons.lang.exception.NestableRuntimeException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.util.FileCopyUtils;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;

public class FileHelper {
    private static final Logger LOGGER = LoggerFactory.getLogger(FileHelper.class);

    public static String fileToString(final String fileName) {
        try {
            return FileCopyUtils.copyToString(new InputStreamReader(new ClassPathResource(fileName).getInputStream()));
        } catch (IOException e) {
            throw new NestableRuntimeException(e);
        }
    }

    public static File addToZipFile(final String zipFilename, final String entryFilename, final String entryContent) throws IOException {
        final File zipFile = File.createTempFile(zipFilename, ".zip");

        final FileOutputStream fileOutputStream = new FileOutputStream(zipFile);
        try {
            final ZipArchiveOutputStream zipArchiveOutputStream = new ZipArchiveOutputStream(fileOutputStream);
            zipArchiveOutputStream.putArchiveEntry(new ZipArchiveEntry(entryFilename));
            IOUtils.write(entryContent.getBytes(), zipArchiveOutputStream);
            zipArchiveOutputStream.closeArchiveEntry();
            zipArchiveOutputStream.finish();
        } finally {
            IOUtils.closeQuietly(fileOutputStream);
        }

        return zipFile;
    }

    public static String convertEOLToUnix(String str) {
        ByteArrayOutputStream resultStream = new ByteArrayOutputStream();
        try {
            LineEnds.convert(IOUtils.toInputStream(str), resultStream, LineEnds.STYLE_UNIX);
        } catch (Exception ex) {
            LOGGER.error("convertEOLToUnix failed", ex);
        }
        return resultStream.toString();
    }

}
