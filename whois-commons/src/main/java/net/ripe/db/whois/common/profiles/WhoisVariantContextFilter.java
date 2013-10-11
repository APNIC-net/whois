package net.ripe.db.whois.common.profiles;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.type.classreading.MetadataReader;
import org.springframework.core.type.classreading.MetadataReaderFactory;
import org.springframework.core.type.filter.TypeFilter;

import java.io.IOException;

public class WhoisVariantContextFilter implements TypeFilter {
    private static final Logger LOGGER = LoggerFactory.getLogger(WhoisVariantContextFilter.class);
    private static final Class annotationClass = WhoisVariantContext.class;


    @Override
    public boolean match(MetadataReader metadataReader, MetadataReaderFactory metadataReaderFactory) throws IOException {
        // Include all beans by default
        boolean exclude = false;

        if (metadataReader.getAnnotationMetadata().hasAnnotation(annotationClass.getCanonicalName())) {
            WhoisVariant.Type variant = WhoisVariant.getWhoIsVariant();
            LOGGER.info(String.format("WhoisVariant [%s] Class [%s]", variant,  metadataReader.getClassMetadata().getClassName()));
            Class clazz;
            try {
                clazz = Class.forName(metadataReader.getClassMetadata().getClassName());
            } catch (ClassNotFoundException cnfe) {
                throw new IOException(String.format("Class could not be loaded by [%s]", getClass().getName()), cnfe);
            }
            WhoisVariantContext whoisVariantContextAnnotation = (WhoisVariantContext) clazz.getAnnotation(annotationClass);

            // If the class contains the @WhoisVariantContext annotation, lets inspect it
            if (whoisVariantContextAnnotation != null) {

                // See if this class should be excluded in the spring context based on whois variant setting and annotation params
                exclude = includeWhenMatch(metadataReader, whoisVariantContextAnnotation, variant);

                // See if this class should be excluded in the spring context based on whois variant setting and annotation params
                if (!exclude) {
                    exclude = excludeWhenMatch(metadataReader, whoisVariantContextAnnotation, variant);
                }
            }
        }
        return exclude;
    }

    private boolean includeWhenMatch(MetadataReader metadataReader, WhoisVariantContext whoisVariantContextAnnotation, WhoisVariant.Type variant) {
        WhoisVariant.Type includeWhen = whoisVariantContextAnnotation.includeWhen();
        boolean exclude = true;
        if (variant == includeWhen) {
            LOGGER.info(String.format("Including bean from spring context based on annotation variant [%s]: %s",variant, metadataReader.getClassMetadata().getClassName()));
            exclude = false;
        } else {
            LOGGER.info(String.format("Excluding bean from spring context based on annotation variant: %s", metadataReader.getClassMetadata().getClassName()));
        }
        return exclude;
    }

    private boolean excludeWhenMatch(MetadataReader metadataReader, WhoisVariantContext whoisVariantContextAnnotation, WhoisVariant.Type variant) {
        WhoisVariant.Type excludeWhen = whoisVariantContextAnnotation.excludeWhen();
        boolean exclude = false;
        if (variant == excludeWhen) {
            LOGGER.info(String.format("Excluding bean from spring context based on annotation variant [%s]: %s", variant, metadataReader.getClassMetadata().getClassName()));
            exclude = true;
        } else {
            LOGGER.info(String.format("Including bean from spring context based on annotation variant: %s", metadataReader.getClassMetadata().getClassName()));
        }
        return exclude;
    }

}
