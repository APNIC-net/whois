package net.ripe.db.whois.api.whois.rdap.domain;

import org.codehaus.jackson.map.annotate.JsonSerialize;
import com.google.common.collect.Lists;

import javax.xml.bind.annotation.*;
import java.io.Serializable;
import java.util.List;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "entity", propOrder = {
        "entityResults",
        "domainResults"
})
@XmlRootElement
@JsonSerialize(include = JsonSerialize.Inclusion.NON_EMPTY)
public class SearchResult extends RdapObject implements Serializable {

    @XmlElement(name = "entitySearchResults")
    protected List<Entity> entityResults;

    @XmlElement(name = "domainSearchResults")
    protected List<Domain> domainResults;

    @XmlElement(name = "resultsTruncated")
    protected Boolean resultsTruncated;

    public List<Entity> getEntitySearchResults() {
        return entityResults;
    }

    public List<Domain> getDomainSearchResults() {
        return domainResults;
    }

    public void addEntitySearchResult(final Entity entity) {
        if (entityResults == null) {
            entityResults = Lists.newArrayList();
        }
        entityResults.add(entity);
    }

    public void addDomainSearchResult(final Domain domain) {
        if (domainResults == null) {
            domainResults = Lists.newArrayList();
        }
        domainResults.add(domain);
    }

    public void isForType(final String objectType) {
        if (objectType.equals("entity")) {
            entityResults = Lists.newArrayList();
        } else if (objectType.equals("domain")) {
            domainResults = Lists.newArrayList();
        }
    }

    public void setResultsTruncated(boolean resultsTruncated) {
        this.resultsTruncated = resultsTruncated;
    }
}
