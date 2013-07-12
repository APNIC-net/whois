package net.ripe.db.whois.api.whois.rdap.domain;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;
import java.util.ArrayList;
import java.util.List;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "notice", propOrder = {
        "errorCode",
        "title",
        "description"
})
@XmlRootElement
public class Exception {
    protected int errorCode;
    protected String title;
    protected List<String> description;

    public void setErrorCode (int errorCode) {
        this.errorCode = errorCode;
    }

    public void setTitle (String title) {
        this.title = title;
    }

    public List<String> getDescription () {
        if (description == null)  {
            return new ArrayList<String>();
        }

        return description;
    }
}
