package net.apnic.db.whois.common.rpsl;

import com.google.common.collect.Maps;
import net.ripe.db.whois.common.rpsl.ObjectType;

import java.util.Map;

public class ObjectDocumentationConfig {
    private static final Map<ObjectType, String> DOCUMENTATION = Maps.newEnumMap(ObjectType.class);

    static {
        DOCUMENTATION.put(ObjectType.AS_BLOCK, "" +
                "      An as-block object is needed to delegate a range of AS numbers \n" +
                "      to a given repository.  This object may be used for authorisation \n" +
                "      of the creation of aut-num objects within the range specified \n" +
                "      by the as-block attribute.\n");

        DOCUMENTATION.put(ObjectType.AS_SET, "" +
                "      An as-set object defines a set of aut-num objects. The as-set \n" +
                "      attribute defines the name of the set. It is an RPSL name that \n" +
                "      starts with \"AS-\". The members attribute lists the members of \n" +
                "      the set. The members attribute is a list of AS numbers, or \n" +
                "      other as-set names.");

        DOCUMENTATION.put(ObjectType.AUT_NUM, "" +
                "      An aut-num object represents an Autonomous System (AS), which is \n" +
                "      a group of IPv4 and IPv6 networks operated by one or more network \n" +
                "      operators that has a single and clearly defined external routing \n" +
                "      policy.");

        DOCUMENTATION.put(ObjectType.DOMAIN, "" +
                "      A domain object represents a reverse DNS delegation domain.");

        DOCUMENTATION.put(ObjectType.FILTER_SET, "" +
                "      A filter-set object defines a set of routes that are matched by \n" +
                "      its filter. The filter-set attribute defines the name of the \n" +
                "      filter. It is an RPSL name that starts with \"FLTR-\". The filter \n" +
                "      attribute defines the set's policy filter. A policy filter is a \n" +
                "      logical expression which when applied to a set of routes returns \n" +
                "      a subset of these routes.");

        DOCUMENTATION.put(ObjectType.INET6NUM, "" +
                "      An inet6num object contains information on allocations \n" +
                "      and assignments of IPv6 address space.");

        DOCUMENTATION.put(ObjectType.INETNUM, "" +
                "      An inetnum object contains information on allocations and \n" +
                "      assignments of IPv4 address space.");

        DOCUMENTATION.put(ObjectType.INET_RTR, "" +
                "      Routers are specified using the inet-rtr class.  The inet-rtr \n" +
                "      attribute is a valid DNS name of the router described. Each \n" +
                "      alias attribute, if present, is a canonical DNS name for the \n" +
                "      router.  The local-as attribute specifies the AS number of the AS \n" +
                "      that owns/operates this router.");

        DOCUMENTATION.put(ObjectType.IRT, "" +
                "      An irt object is used to define a Computer Security Incident \n" +
                "      Response Team (CSIRT).");

        DOCUMENTATION.put(ObjectType.KEY_CERT, "" +
                "      A key-cert object is a database public key certificate \n" +
                "      that is stored on the server and may be used with a mntner \n" +
                "      object for authentication when performing updates. \n" +
                "      Currently only PGP/GnuPG keys are supported.");

        DOCUMENTATION.put(ObjectType.MNTNER, "" +
                "      Objects in the APNIC Whois Database may be protected using \n" +
                "      mntner (maintainer) objects. A mntner object specifies \n" +
                "      authentication information required to authorise creation, \n" +
                "      deletion or modification of the objects protected by the mntner. \n" +
                "\n" +
                "      Mntner objects cannot be created automatically. To create a \n" +
                "      new maintainer, you must forward the object to the APNIC \n" +
                "      Whois Database Administration (maint-request@apnic.net).");

        DOCUMENTATION.put(ObjectType.ORGANISATION, "" +
                "      The organisation class provides information identifying  \n" +
                "      an organisation such as a company, charity or university, \n" +
                "      that is a holder of a network resource whose data is stored \n" +
                "      in the whois database.");

        DOCUMENTATION.put(ObjectType.PEERING_SET, "" +
                "      A peering-set object defines a set of peerings that are listed \n" +
                "      in its peering attributes.  The peering-set attribute \n" +
                "      defines the name of the set.");

        DOCUMENTATION.put(ObjectType.PERSON, "" +
                "      Contains information about a technical, administrative or zone\n" +
                "      contact responsible for the object where it is referenced.\n" +
                "\n" +
                "      Note: once the object is created, the value of the person\n" +
                "      attribute cannot be changed. To change the value of the person\n" +
                "      attribute, please delete the existing person object and submit a\n" +
                "      new one.");

        DOCUMENTATION.put(ObjectType.POEM, "" +
                "      This object is not allowed.\n");

        DOCUMENTATION.put(ObjectType.POETIC_FORM, "" +
                "      This object is not allowed. \n");

        DOCUMENTATION.put(ObjectType.ROLE, "" +
                "      The role object is similar to a person object. However, instead \n" +
                "      of describing a person, it describes a role performed by one or \n" +
                "      more people, for example, a help desk or network operation \n" +
                "      centre. A role object is particularly useful since often a person \n" +
                "      performing a role may change; however the role itself remains. \n" +
                "      The nic-hdl attributes of the person and role objects share \n" +
                "      the same name space. \n" +
                "\n" +
                "      Note: once the object is created, the value of the role \n" +
                "      attribute cannot be changed.To change the value of the role \n" +
                "      attribute, please delete the existing person object and submit \n" +
                "      a new one.");

        DOCUMENTATION.put(ObjectType.ROUTE, "" +
                "      Each interAS route (also referred to as an interdomain route) \n" +
                "      originated by an AS is specified using a route object. The route \n" +
                "      attribute is the address prefix of the route and the origin \n" +
                "      attribute is the AS number of the AS that originates the route \n" +
                "      into the interAS routing system.");

        DOCUMENTATION.put(ObjectType.ROUTE6, "" +
                "      Each interAS route (also referred to as an interdomain route)\n" +
                "      in IPv6 domain originated by an AS is specified using a route6 \n" +
                "      object. The route6 attribute is the address prefix of the \n" +
                "      route and the origin attribute is the AS number of the AS \n" +
                "      that originates the route into the interAS routing system.");

        DOCUMENTATION.put(ObjectType.ROUTE_SET, "" +
                "      A route-set object defines a set of routes that can be \n" +
                "      represented by route objects or by address prefixes. In the \n" +
                "      first case, the set is populated by means of the mbrs-by-ref \n" +
                "      attribute, in the latter, the members of the set are explicitly \n" +
                "      listed in the members and mp-members attributes. The members and \n" +
                "      mp-members attributes are a list of address prefixes or other \n" +
                "      route-set names. Note that the route-set object is a set of \n" +
                "      route prefixes, not of database route objects.");

        DOCUMENTATION.put(ObjectType.RTR_SET, "" +
                "      The rtr-set object defines a set of routers. A set may be \n" +
                "      described by the members and mp-members attributes, which are a \n" +
                "      list of inet-rtr names, IPv4 and Ipv6 addresses or other rtr-set \n" +
                "      names. A set may also be  populated by means of the mbrs-by-ref \n" +
                "       attribute, in which case it is represented by inet-rtr objects.");
    }

    public static Map<ObjectType, String> getDocumentationImpl() {
        return DOCUMENTATION;
    }

}
