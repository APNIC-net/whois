package net.ripe.db.whois.api.whois;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import net.ripe.db.whois.api.whois.domain.*;
import net.ripe.db.whois.common.domain.CIString;
import net.ripe.db.whois.common.rpsl.AttributeTemplate;
import net.ripe.db.whois.common.rpsl.ObjectTemplate;
import net.ripe.db.whois.common.rpsl.ObjectType;
import net.ripe.db.whois.common.source.SourceContext;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.Collections;
import java.util.List;
import java.util.Map;

@Component
@Path("/metadata")
public class WhoisMetadata {

    // we cannot get this from metadata, as we have two separate JVMs running for each source
    private final List<Source> SOURCES = ImmutableList.of(
            new Source("ripe").setName("RIPE"),
            new Source("test").setName("TEST"));

    private final List<GrsSource> GRSSOURCES;

    private final Map<String, Template> ATTRIBUTE_TEMPLATES;

    @Autowired
    public WhoisMetadata(SourceContext sourceContext) {

        GRSSOURCES = Lists.newArrayList();
        for (CIString source: sourceContext.getGrsSourceNames()) {
            final String id = source.toLowerCase();
            GRSSOURCES.add(new GrsSource(id).setGrsId(id).setName(id.toUpperCase()));
        }

        Source ripeSource = new Source("ripe");

        ATTRIBUTE_TEMPLATES = Maps.newHashMap();
        for (ObjectType objectType : ObjectType.values()) {
            ObjectTemplate objectTemplate = ObjectTemplate.getTemplate(objectType);
            List<TemplateAttribute> templateAttributes = Lists.newArrayList();

            for (AttributeTemplate attributeTemplate : objectTemplate.getAttributeTemplates()) {

                templateAttributes.add(new TemplateAttribute()
                        .setName(attributeTemplate.getAttributeType().getName())
                        .setCardinality(attributeTemplate.getCardinality())
                        .setRequirement(attributeTemplate.getRequirement())
                        .setKey(attributeTemplate.getKeys()));

            }

            Template template = new Template()
                    .setSource(ripeSource)
                    .setType(objectType.getName())
                    .setAttributes(templateAttributes);

            ATTRIBUTE_TEMPLATES.put(objectType.getName(), template);
        }
    }

    /**
     * @return Returns all available sources.
     */
    @GET
    @Produces({MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON})
    @Path("/sources")
    public Response sources() {
        WhoisResources result = new WhoisResources()
            .setService("getSupportedDataSources")
            .setLink(new Link("locator", "http://rest.db.ripe.net/metadata/sources"))
            .setSources(SOURCES)
            .setGrsSources(GRSSOURCES);
        return Response.ok(result).build();
    }

    /**
     * @param objectType The object type for which the template is requested
     * @return Returns the object template for requested type
     */
    @GET
    @Produces({MediaType.APPLICATION_XML, MediaType.APPLICATION_JSON})
    @Path("/templates/{objectType}")
    public Response templates(@PathParam("objectType") String objectType) {
        final Template template = ATTRIBUTE_TEMPLATES.get(objectType);
        if (template == null) {
            return Response.status(HttpServletResponse.SC_NOT_FOUND).build();
        }

        TemplateResources result = new TemplateResources()
                .setService("getObjectTemplate")
                .setLink(new Link("locator", "http://rest.db.ripe.net/metadata/templates/"+objectType))
                .setTemplates(Collections.singletonList(template));

        return Response.ok(result).build();
    }
}
