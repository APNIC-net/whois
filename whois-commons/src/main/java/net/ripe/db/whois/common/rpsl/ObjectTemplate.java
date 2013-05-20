package net.ripe.db.whois.common.rpsl;

import com.google.common.base.Function;
import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import net.ripe.db.whois.common.profiles.WhoisVariant;
import org.apache.commons.lang.WordUtils;

import javax.annotation.Nullable;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static net.ripe.db.whois.common.rpsl.AttributeTemplate.Cardinality.SINGLE;
import static net.ripe.db.whois.common.rpsl.AttributeTemplate.Key;
import static net.ripe.db.whois.common.rpsl.AttributeTemplate.Key.INVERSE_KEY;
import static net.ripe.db.whois.common.rpsl.AttributeTemplate.Key.LOOKUP_KEY;
import static net.ripe.db.whois.common.rpsl.AttributeTemplate.Key.PRIMARY_KEY;
import static net.ripe.db.whois.common.rpsl.AttributeTemplate.Requirement.GENERATED;
import static net.ripe.db.whois.common.rpsl.AttributeTemplate.Requirement.MANDATORY;

public class ObjectTemplate implements Comparable<ObjectTemplate> {
    private static final Map<ObjectType, ObjectTemplate> TEMPLATE_MAP;

    static {
        if (WhoisVariant.isAPNIC()) {
            TEMPLATE_MAP = net.apnic.db.whois.common.rpsl.ObjectTemplateMapConfig.getTemplateMap();
        } else {
            TEMPLATE_MAP = ObjectTemplateMapConfig.getTemplateMap();
        }
    }

    private final ObjectType objectType;
    private final int orderPosition;
    private final Map<AttributeType, AttributeTemplate> attributeTemplateMap;
    private final List<AttributeTemplate> attributeTemplates;
    private final Set<AttributeType> allAttributeTypes;
    private final Set<AttributeType> keyAttributes;
    private final Set<AttributeType> lookupAttributes;
    private final Set<AttributeType> inverseLookupAttributes;
    private final Set<AttributeType> mandatoryAttributes;

    public ObjectTemplate(final ObjectType objectType, final int orderPosition, final AttributeTemplate... attributeTemplates) {
        this.objectType = objectType;
        this.orderPosition = orderPosition;

        this.attributeTemplates = Collections.unmodifiableList(Lists.newArrayList(attributeTemplates));
        this.allAttributeTypes = Collections.unmodifiableSet(Sets.newLinkedHashSet(Iterables.transform(this.attributeTemplates, new Function<AttributeTemplate, AttributeType>() {
            @Nullable
            @Override
            public AttributeType apply(final AttributeTemplate input) {
                return input.getAttributeType();
            }
        })));

        this.attributeTemplateMap = Maps.newEnumMap(AttributeType.class);
        for (final AttributeTemplate attributeTemplate : attributeTemplates) {
            this.attributeTemplateMap.put(attributeTemplate.getAttributeType(), attributeTemplate);
        }

        keyAttributes = getAttributes(attributeTemplates, PRIMARY_KEY);
        lookupAttributes = getAttributes(attributeTemplates, LOOKUP_KEY);
        inverseLookupAttributes = getAttributes(attributeTemplates, INVERSE_KEY);
        mandatoryAttributes = getAttributes(attributeTemplates, MANDATORY);
    }

    protected Set<AttributeType> getAttributes(final AttributeTemplate[] attributeTemplates, final Key key) {
        final Set<AttributeType> attributeTypes = Sets.newLinkedHashSet();
        for (final AttributeTemplate attributeTemplate : attributeTemplates) {
            if (attributeTemplate.getKeys().contains(key)) {
                attributeTypes.add(attributeTemplate.getAttributeType());
            }
        }

        return Collections.unmodifiableSet(attributeTypes);
    }

    protected Set<AttributeType> getAttributes(final AttributeTemplate[] attributeTemplates, final AttributeTemplate.Requirement requirement) {
        final Set<AttributeType> attributeTypes = Sets.newLinkedHashSet();
        for (final AttributeTemplate attributeTemplate : attributeTemplates) {
            if (attributeTemplate.getRequirement() == requirement) {
                attributeTypes.add(attributeTemplate.getAttributeType());
            }
        }

        return Collections.unmodifiableSet(attributeTypes);
    }

    public static ObjectTemplate getTemplate(final ObjectType type) {
        final ObjectTemplate objectTemplate = TEMPLATE_MAP.get(type);
        if (objectTemplate == null) {
            throw new IllegalStateException("No template for " + type);
        }

        return objectTemplate;
    }

    public ObjectType getObjectType() {
        return objectType;
    }

    public List<AttributeTemplate> getAttributeTemplates() {
        return attributeTemplates;
    }

    public Set<AttributeType> getAllAttributes() {
        return allAttributeTypes;
    }

    public Set<AttributeType> getKeyAttributes() {
        return keyAttributes;
    }

    public Set<AttributeType> getLookupAttributes() {
        return lookupAttributes;
    }

    public Set<AttributeType> getMandatoryAttributes() {
        return mandatoryAttributes;
    }

    public Set<AttributeType> getInverseLookupAttributes() {
        return inverseLookupAttributes;
    }

    public boolean isSet() {
        return ObjectType.getSets().contains(objectType);
    }

    @Override
    public boolean equals(final Object o) {
        return this == o || !(o == null || getClass() != o.getClass()) && objectType == ((ObjectTemplate) o).objectType;
    }

    @Override
    public int hashCode() {
        return objectType.hashCode();
    }

    @Override
    public int compareTo(final ObjectTemplate o) {
        return orderPosition - o.orderPosition;
    }

    public ObjectMessages validate(final RpslObject rpslObject) {
        final ObjectMessages objectMessages = new ObjectMessages();
        final ObjectType objectType = rpslObject.getType();

        final Map<AttributeType, Integer> attributeCount = Maps.newEnumMap(AttributeType.class);
        for (final AttributeTemplate attributeTemplate : attributeTemplates) {
            attributeCount.put(attributeTemplate.getAttributeType(), 0);
        }

        for (final RpslAttribute attribute : rpslObject.getAttributes()) {
            final AttributeType attributeType = attribute.getType();
            if (attributeType == null) {
                objectMessages.addMessage(attribute, ValidationMessages.unknownAttribute(attribute.getKey()));
            } else {
                final AttributeTemplate attributeTemplate = attributeTemplateMap.get(attributeType);
                if (attributeTemplate == null) {
                    objectMessages.addMessage(attribute, ValidationMessages.invalidAttributeForObject(attributeType));
                } else if (!attributeTemplate.getRequirement().equals(GENERATED)) {
                    attribute.validateSyntax(objectType, objectMessages);
                    attributeCount.put(attributeType, attributeCount.get(attributeType) + 1);
                }
            }
        }

        for (final AttributeTemplate attributeTemplate : attributeTemplates) {
            final AttributeType attributeType = attributeTemplate.getAttributeType();
            final int count = attributeCount.get(attributeType);

            if (MANDATORY.equals(attributeTemplate.getRequirement()) && count == 0) {
                objectMessages.addMessage(ValidationMessages.missingMandatoryAttribute(attributeType));
            }

            if (SINGLE.equals(attributeTemplate.getCardinality()) && count > 1) {
                objectMessages.addMessage(ValidationMessages.tooManyAttributesOfType(attributeType));
            }
        }

        return objectMessages;
    }

    @Override
    public String toString() {
        final StringBuilder result = new StringBuilder();

        for (final AttributeTemplate attributeTemplate : attributeTemplates) {
            result.append(attributeTemplate).append('\n');
        }

        return result.toString();
    }

    public String toVerboseString() {
        final StringBuilder result = new StringBuilder();

        result.append("The ")
                .append(objectType.getName())
                .append(" class:\n\n")
                .append(ObjectDocumentation.getDocumentation(objectType))
                .append('\n')
                .append(toString())
                .append("\nThe content of the attributes of the ")
                .append(objectType.getName())
                .append(" class are defined below:\n\n");

        for (final AttributeTemplate attributeTemplate : attributeTemplates) {
            final AttributeType attributeType = attributeTemplate.getAttributeType();

            String attributeDescription = attributeType.getDescription(objectType);
            if (attributeDescription.indexOf('\n') == -1) {
                attributeDescription = WordUtils.wrap(attributeDescription, 70);
            }

            if (attributeDescription.endsWith("\n")) {
                attributeDescription = attributeDescription.substring(0, attributeDescription.length() - 1);
            }

            String syntaxDescription = attributeType.getSyntax().getDescription(objectType);
            if (syntaxDescription.endsWith("\n")) {
                syntaxDescription = syntaxDescription.substring(0, syntaxDescription.length() - 1);
            }

            result.append(attributeType.getName())
                    .append("\n\n   ")
                    .append(attributeDescription.replaceAll("\n", "\n   "))
                    .append("\n\n     ")
                    .append(syntaxDescription.replaceAll("\n", "\n     "))
                    .append("\n\n");
        }

        return result.toString();
    }

    public boolean hasAttribute(final AttributeType attributeType) {
        return getAllAttributes().contains(attributeType);
    }
}
