package net.apnic.db.whois.spec.query

import net.apnic.db.whois.spec.BaseSpec
import net.apnic.db.whois.spec.helper.TemplateObject

class TemplateSpec extends BaseSpec {
    def "as-block"() {
      when:
        def template = new TemplateObject("as-block")

      then:
        template.description =~ /as-block/
        template.basicTemplate == [
                ["as-block",    "mandatory",    "single",   "primary/lookup key"],
                ["descr",       "optional",     "multiple", ""],
                ["remarks",     "optional",     "multiple", ""],
                ["country",     "optional",     "single",   ""],
                ["admin-c",     "mandatory",    "multiple", "inverse key"],
                ["tech-c",      "mandatory",    "multiple", "inverse key"],
                ["org",         "optional",     "multiple", "inverse key"],
                ["notify",      "optional",     "multiple", "inverse key"],
                ["mnt-by",      "mandatory",    "multiple", "inverse key"],
                ["mnt-lower",   "optional",     "multiple", "inverse key"],
                ["changed",     "mandatory",    "multiple", ""],
                ["source",      "mandatory",    "single",   ""],
        ]
        template.getAttributeDescription("country") =~ /AP/
        template.getAttributeDescription("country") =~ /EU/
        template.getAttributeDescription("admin-c") =~ /-AP/
        template.getAttributeDescription("tech-c") =~ /-AP/
        template.getAttributeDescription("source") =~ /APNIC/
    }

    def "as-set"() {
      when:
        def template = new TemplateObject("as-set")

      then:
        template.description =~ /as-set/
        template.basicTemplate == [
                ["as-set",      "mandatory",    "single",   "primary/lookup key"],
                ["descr",       "mandatory",    "multiple", ""],
                ["country",     "optional",     "single",   ""],
                ["members",     "optional",     "multiple", ""],
                ["mbrs-by-ref", "optional",     "multiple", "inverse key"],
                ["remarks",     "optional",     "multiple", ""],
                ["org",         "optional",     "multiple", "inverse key"],
                ["tech-c",      "mandatory",    "multiple", "inverse key"],
                ["admin-c",     "mandatory",    "multiple", "inverse key"],
                ["notify",      "optional",     "multiple", "inverse key"],
                ["mnt-by",      "mandatory",    "multiple", "inverse key"],
                ["mnt-lower",   "optional",     "multiple", "inverse key"],
                ["changed",     "mandatory",    "multiple", ""],
                ["source",      "mandatory",    "single",   ""],
        ]
        template.getAttributeDescription("country") =~ /AP/
        template.getAttributeDescription("country") =~ /EU/
        template.getAttributeDescription("tech-c") =~ /-AP/
        template.getAttributeDescription("admin-c") =~ /-AP/
        template.getAttributeDescription("source") =~ /APNIC/
    }

    def "aut-num"() {
      when:
        def template = new TemplateObject("aut-num")

      then:
        template.description =~ /aut-num/
        template.basicTemplate == [
                ["aut-num",     "mandatory",    "single",   "primary/lookup key"],
                ["as-name",     "mandatory",    "single",   ""],
                ["descr",       "mandatory",    "multiple", ""],
                ["country",     "mandatory",    "single",   ""],
                ["member-of",   "optional",     "multiple", "inverse key"],
                ["import",      "optional",     "multiple", ""],
                ["mp-import",   "optional",     "multiple", ""],
                ["export",      "optional",     "multiple", ""],
                ["mp-export",   "optional",     "multiple", ""],
                ["default",     "optional",     "multiple", ""],
                ["mp-default",  "optional",     "multiple", ""],
                ["remarks",     "optional",     "multiple", ""],
                ["org",         "optional",     "single",   "inverse key"],
                ["admin-c",     "mandatory",    "multiple", "inverse key"],
                ["tech-c",      "mandatory",    "multiple", "inverse key"],
                ["notify",      "optional",     "multiple", "inverse key"],
                ["mnt-lower",   "optional",     "multiple", "inverse key"],
                ["mnt-routes",  "optional",     "multiple", "inverse key"],
                ["mnt-by",      "mandatory",    "multiple", "inverse key"],
                ["mnt-irt",     "mandatory",    "multiple", "inverse key"],
                ["changed",     "mandatory",    "multiple", ""],
                ["source",      "mandatory",    "single",   ""],
        ]
        template.getAttributeDescription("country") =~ /AP/
        template.getAttributeDescription("country") =~ /EU/
        template.getAttributeDescription("admin-c") =~ /-AP/
        template.getAttributeDescription("tech-c") =~ /-AP/
        template.getAttributeDescription("source") =~ /APNIC/
    }

    def "domain"() {
      when:
        def template = new TemplateObject("domain")

      then:
        template.description =~ /domain/
        template.basicTemplate == [
                ["domain",      "mandatory",    "single",   "primary/lookup key"],
                ["descr",       "mandatory",    "multiple", ""],
                ["country",     "optional",     "single",   ""],
                ["org",         "optional",     "multiple", "inverse key"],
                ["admin-c",     "mandatory",    "multiple", "inverse key"],
                ["tech-c",      "mandatory",    "multiple", "inverse key"],
                ["zone-c",      "mandatory",    "multiple", "inverse key"],
                ["nserver",     "optional",     "multiple", "inverse key"],
                ["ds-rdata",    "optional",     "multiple", "inverse key"],
                ["remarks",     "optional",     "multiple", ""],
                ["notify",      "optional",     "multiple", "inverse key"],
                ["mnt-by",      "mandatory",    "multiple", "inverse key"],
                ["mnt-lower",   "optional",     "multiple", "inverse key"],
// TODO confirm the refer attribute removal
//                ["refer",       "optional",     "single",   ""],
                ["changed",     "mandatory",    "multiple", ""],
                ["source",      "mandatory",    "single",   ""],
        ]
        template.getAttributeDescription("country") =~ /AP/
        template.getAttributeDescription("country") =~ /EU/
        template.getAttributeDescription("admin-c") =~ /-AP/
        template.getAttributeDescription("tech-c") =~ /-AP/
        template.getAttributeDescription("zone-c") =~ /-AP/
        template.getAttributeDescription("source") =~ /APNIC/
    }

    def "filter-set"() {
        when:
        def template = new TemplateObject("filter-set")

        then:
        template.description =~ /filter-set/
        template.basicTemplate == [
                ["filter-set",  "mandatory",    "single",   "primary/lookup key"],
                ["descr",       "mandatory",    "multiple", ""],
                ["filter",      "optional",     "single",   ""],
                ["mp-filter",   "optional",     "single",   ""],
                ["remarks",     "optional",     "multiple", ""],
                ["org",         "optional",     "multiple", "inverse key"],
                ["tech-c",      "mandatory",    "multiple", "inverse key"],
                ["admin-c",     "mandatory",    "multiple", "inverse key"],
                ["notify",      "optional",     "multiple", "inverse key"],
                ["mnt-by",      "mandatory",    "multiple", "inverse key"],
                ["mnt-lower",   "optional",     "multiple", "inverse key"],
                ["changed",     "mandatory",    "multiple", ""],
                ["source",      "mandatory",    "single",   ""],
        ]
        template.getAttributeDescription("tech-c") =~ /-AP/
        template.getAttributeDescription("admin-c") =~ /-AP/
        template.getAttributeDescription("source") =~ /APNIC/
    }

    def "inet-rtr"() {
      when:
        def template = new TemplateObject("inet-rtr")

      then:
        template.description =~ /inet-rtr/
        template.basicTemplate == [
                ["inet-rtr",    "mandatory",    "single",   "primary/lookup key"],
                ["descr",       "mandatory",    "multiple", ""],
                ["alias",       "optional",     "multiple", ""],
                ["local-as",    "mandatory",    "single",   "inverse key"],
                ["ifaddr",      "mandatory",    "multiple", "inverse key"],
                ["interface",   "optional",     "multiple", ""],
                ["peer",        "optional",     "multiple", ""],
                ["mp-peer",     "optional",     "multiple", ""],
                ["member-of",   "optional",     "multiple", "inverse key"],
                ["remarks",     "optional",     "multiple", ""],
                ["org",         "optional",     "multiple", "inverse key"],
                ["admin-c",     "mandatory",    "multiple", "inverse key"],
                ["tech-c",      "mandatory",    "multiple", "inverse key"],
                ["notify",      "optional",     "multiple", "inverse key"],
                ["mnt-by",      "mandatory",    "multiple", "inverse key"],
                ["changed",     "mandatory",    "multiple", ""],
                ["source",      "mandatory",    "single",   ""],
        ]
        template.getAttributeDescription("admin-c") =~ /-AP/
        template.getAttributeDescription("tech-c") =~ /-AP/
        template.getAttributeDescription("source") =~ /APNIC/
    }

    def "inet6num"() {
      when:
        def template = new TemplateObject("inet6num")

      then:
        template.description =~ /inet6num/
        template.basicTemplate == [
                ["inet6num",    "mandatory",    "single",   "primary/lookup key"],
                ["netname",     "mandatory",    "single",   "lookup key"],
                ["descr",       "mandatory",    "multiple", ""],
                ["country",     "mandatory",    "multiple", ""],
                ["geoloc",      "optional",     "single",   ""],
                ["language",    "optional",     "multiple", ""],
                ["org",         "optional",     "single",   "inverse key"],
                ["admin-c",     "mandatory",    "multiple", "inverse key"],
                ["tech-c",      "mandatory",    "multiple", "inverse key"],
                ["status",      "mandatory",    "single",   ""],
                ["remarks",     "optional",     "multiple", ""],
                ["notify",      "optional",     "multiple", "inverse key"],
                ["mnt-by",      "mandatory",    "multiple", "inverse key"],
                ["mnt-lower",   "optional",     "multiple", "inverse key"],
                ["mnt-routes",  "optional",     "multiple", "inverse key"],
                ["mnt-irt",     "mandatory",    "multiple", "inverse key"],
                ["changed",     "mandatory",    "multiple", ""],
                ["source",      "mandatory",    "single",   ""],
        ]
        template.getAttributeDescription("country") =~ /AP/
        template.getAttributeDescription("country") =~ /EU/
        template.getAttributeDescription("admin-c") =~ /-AP/
        template.getAttributeDescription("tech-c") =~ /-AP/
        template.getAttributeDescription("status") =~ /ALLOCATED PORTABLE/
        template.getAttributeDescription("status") =~ /ALLOCATED NON-PORTABLE/
        template.getAttributeDescription("status") =~ /ASSIGNED PORTABLE/
        template.getAttributeDescription("status") =~ /ASSIGNED NON-PORTABLE/
        template.getAttributeDescription("source") =~ /APNIC/
    }

    def "inetnum"() {
      when:
        def template = new TemplateObject("inetnum")

      then:
        template.description =~ /inetnum/
        template.basicTemplate == [
                ["inetnum",     "mandatory",    "single",   "primary/lookup key"],
                ["netname",     "mandatory",    "single",   "lookup key"],
                ["descr",       "mandatory",    "multiple", ""],
                ["country",     "mandatory",    "multiple", ""],
                ["geoloc",      "optional",     "single",   ""],
                ["language",    "optional",     "multiple", ""],
                ["org",         "optional",     "single",   "inverse key"],
                ["admin-c",     "mandatory",    "multiple", "inverse key"],
                ["tech-c",      "mandatory",    "multiple", "inverse key"],
                ["status",      "mandatory",    "single",   ""],
                ["remarks",     "optional",     "multiple", ""],
                ["notify",      "optional",     "multiple", "inverse key"],
                ["mnt-by",      "mandatory",    "multiple", "inverse key"],
                ["mnt-lower",   "optional",     "multiple", "inverse key"],
                ["mnt-routes",  "optional",     "multiple", "inverse key"],
                ["mnt-irt",     "mandatory",    "multiple", "inverse key"],
                ["changed",     "mandatory",    "multiple", ""],
                ["source",      "mandatory",    "single",   ""],
        ]
        template.getAttributeDescription("country") =~ /AP/
        template.getAttributeDescription("country") =~ /EU/
        template.getAttributeDescription("admin-c") =~ /-AP/
        template.getAttributeDescription("tech-c") =~ /-AP/
        template.getAttributeDescription("status") =~ /ALLOCATED PORTABLE/
        template.getAttributeDescription("status") =~ /ALLOCATED NON-PORTABLE/
        template.getAttributeDescription("status") =~ /ASSIGNED PORTABLE/
        template.getAttributeDescription("status") =~ /ASSIGNED NON-PORTABLE/
        template.getAttributeDescription("source") =~ /APNIC/
    }

    def "irt"() {
        when:
        def template = new TemplateObject("irt")

        then:
        template.description =~ /irt/
        template.basicTemplate == [
                ["irt",         "mandatory",    "single",   "primary/lookup key"],
                ["address",     "mandatory",    "multiple", ""],
                ["phone",       "optional",     "multiple", ""],
                ["fax-no",      "optional",     "multiple", ""],
                ["e-mail",      "mandatory",    "multiple", "lookup key"],
                ["abuse-mailbox","mandatory",    "multiple", "inverse key"],
                ["signature",   "optional",     "multiple", ""],
                ["encryption",  "optional",     "multiple", ""],
                ["org",         "optional",     "multiple", "inverse key"],
                ["admin-c",     "mandatory",    "multiple", "inverse key"],
                ["tech-c",      "mandatory",    "multiple", "inverse key"],
                ["auth",        "mandatory",    "multiple", "inverse key"],
                ["remarks",     "optional",     "multiple", ""],
                ["irt-nfy",     "optional",     "multiple", "inverse key"],
                ["notify",      "optional",     "multiple", "inverse key"],
                ["mnt-by",      "mandatory",    "multiple", "inverse key"],
                ["changed",     "mandatory",    "multiple", ""],
                ["source",      "mandatory",    "single",   ""],
        ]
        template.getAttributeDescription("admin-c") =~ /-AP/
        template.getAttributeDescription("tech-c") =~ /-AP/
        template.getAttributeDescription("auth") =~ /MD5-PW/
        template.getAttributeDescription("source") =~ /APNIC/
    }

    def "key-cert"() {
      when:
        def template = new TemplateObject("key-cert")

      then:
        template.description =~ /key-cert/
        template.basicTemplate == [
                ["key-cert",    "mandatory",    "single",   "primary/lookup key"],
                ["method",      "generated",    "single",   ""],
                ["owner",       "generated",    "multiple", ""],
                ["fingerpr",    "generated",    "single",   "inverse key"],
                ["certif",      "mandatory",    "multiple", ""],
                ["org",         "optional",     "multiple", "inverse key"],
                ["remarks",     "optional",     "multiple", ""],
                ["notify",      "optional",     "multiple", "inverse key"],
                ["admin-c",     "optional",     "multiple", "inverse key"],
                ["tech-c",      "optional",     "multiple", "inverse key"],
                ["mnt-by",      "mandatory",    "multiple", "inverse key"],
                ["changed",     "mandatory",    "multiple", ""],
                ["source",      "mandatory",    "single",   ""],
        ]
        template.getAttributeDescription("admin-c") =~ /-AP/
        template.getAttributeDescription("tech-c") =~ /-AP/
        template.getAttributeDescription("source") =~ /APNIC/
    }

    def "mntner"() {
      when:
        def template = new TemplateObject("mntner")

      then:
        template.description =~ /mntner/
        template.basicTemplate == [
                ["mntner",      "mandatory",    "single",   "primary/lookup key"],
                ["descr",       "mandatory",    "multiple", ""],
                ["country",     "optional",     "single",   ""],
                ["org",         "optional",     "multiple", "inverse key"],
                ["admin-c",     "mandatory",    "multiple", "inverse key"],
                ["tech-c",      "optional",     "multiple", "inverse key"],
                ["upd-to",      "mandatory",    "multiple", "inverse key"],
                ["mnt-nfy",     "optional",     "multiple", "inverse key"],
                ["auth",        "mandatory",    "multiple", "inverse key"],
                ["remarks",     "optional",     "multiple", ""],
                ["notify",      "optional",     "multiple", "inverse key"],
                ["abuse-mailbox","optional",    "multiple", "inverse key"],
                ["mnt-by",      "mandatory",    "multiple", "inverse key"],
                ["referral-by", "mandatory",    "single",   "inverse key"],
                ["changed",     "mandatory",    "multiple", ""],
                ["source",      "mandatory",    "single",   ""],
        ]
        template.getAttributeDescription("country") =~ /AP/
        template.getAttributeDescription("country") =~ /EU/
        template.getAttributeDescription("admin-c") =~ /-AP/
        template.getAttributeDescription("tech-c") =~ /-AP/
        template.getAttributeDescription("auth") =~ /MD5-PW/
        template.getAttributeDescription("source") =~ /APNIC/
    }

    def "organisation"() {
        when:
        def template = new TemplateObject("organisation")

        then:
        template.description =~ /organisation/
        template.basicTemplate == [
                ["organisation","mandatory",    "single",   "primary/lookup key"],
                ["org-name",    "mandatory",    "single",   "lookup key"],
                ["org-type",    "mandatory",    "single",   ""],
                ["descr",       "optional",     "multiple", ""],
                ["country",     "optional",     "multiple", ""],
                ["address",     "mandatory",    "multiple", ""],
                ["phone",       "optional",     "multiple", ""],
                ["fax-no",      "optional",     "multiple", ""],
                ["e-mail",      "mandatory",    "multiple", "lookup key"],
                ["geoloc",      "optional",     "single",   ""],
                ["language",    "optional",     "multiple", ""],
                ["org",         "optional",     "multiple", "inverse key"],
                ["admin-c",     "optional",     "multiple", "inverse key"],
                ["tech-c",      "optional",     "multiple", "inverse key"],
                ["ref-nfy",     "optional",     "multiple", "inverse key"],
                ["mnt-ref",     "mandatory",    "multiple", "inverse key"],
                ["notify",      "optional",     "multiple", "inverse key"],
                ["abuse-mailbox","optional",    "multiple", "inverse key"],
                ["mnt-by",      "mandatory",    "multiple", "inverse key"],
                ["changed",     "mandatory",    "multiple", ""],
                ["source",      "mandatory",    "single",   ""],
        ]
        template.getAttributeDescription("admin-c") =~ /-AP/
        template.getAttributeDescription("tech-c") =~ /-AP/
        template.getAttributeDescription("source") =~ /APNIC/
    }

    def "peering-set"() {
        when:
        def template = new TemplateObject("peering-set")

        then:
        template.description =~ /peering-set/
        template.basicTemplate == [
                ["peering-set", "mandatory",    "single",   "primary/lookup key"],
                ["descr",       "mandatory",    "multiple", ""],
                ["peering",     "optional",     "multiple", ""],
                ["mp-peering",  "optional",     "multiple", ""],
                ["remarks",     "optional",     "multiple", ""],
                ["org",         "optional",     "multiple", "inverse key"],
                ["tech-c",      "mandatory",    "multiple", "inverse key"],
                ["admin-c",     "mandatory",    "multiple", "inverse key"],
                ["notify",      "optional",     "multiple", "inverse key"],
                ["mnt-by",      "mandatory",    "multiple", "inverse key"],
                ["mnt-lower",   "optional",     "multiple", "inverse key"],
                ["changed",     "mandatory",    "multiple", ""],
                ["source",      "mandatory",    "single",   ""],
        ]
        template.getAttributeDescription("tech-c") =~ /-AP/
        template.getAttributeDescription("admin-c") =~ /-AP/
        template.getAttributeDescription("source") =~ /APNIC/
    }

    def "person"() {
      when:
        def template = new TemplateObject("person")

      then:
        template.description =~ /person/
        template.basicTemplate == [
                ["person",      "mandatory",    "single",   "lookup key"],
                ["address",     "mandatory",    "multiple", ""],
                ["country",     "mandatory",    "single",   ""],
                ["phone",       "mandatory",    "multiple", ""],
                ["fax-no",      "optional",     "multiple", ""],
                ["e-mail",      "mandatory",    "multiple", "lookup key"],
                ["org",         "optional",     "multiple", "inverse key"],
                ["nic-hdl",     "mandatory",    "single",   "primary/lookup key"],
                ["remarks",     "optional",     "multiple", ""],
                ["notify",      "optional",     "multiple", "inverse key"],
                ["abuse-mailbox","optional",     "multiple", "inverse key"],
                ["mnt-by",      "mandatory",    "multiple", "inverse key"],
                ["changed",     "mandatory",    "multiple", ""],
                ["source",      "mandatory",    "single",   ""],
        ]
        template.getAttributeDescription("country") =~ /AP/
        template.getAttributeDescription("country") =~ /EU/
        template.getAttributeDescription("nic-hdl") =~ /-AP/
        template.getAttributeDescription("source") =~ /APNIC/
    }

    def "role"() {
      when:
        def template = new TemplateObject("role")

      then:
        template.description =~ /role/
        template.basicTemplate == [
                ["role",        "mandatory",    "single",   "lookup key"],
                ["address",     "mandatory",    "multiple", ""],
                ["country",     "mandatory",    "single",   ""],
                ["phone",       "mandatory",    "multiple", ""],
                ["fax-no",      "optional",     "multiple", ""],
                ["e-mail",      "mandatory",    "multiple", "lookup key"],
                ["org",         "optional",     "multiple", "inverse key"],
                ["admin-c",     "mandatory",    "multiple", "inverse key"],
                ["tech-c",      "mandatory",    "multiple", "inverse key"],
                ["nic-hdl",     "mandatory",    "single",   "primary/lookup key"],
                ["remarks",     "optional",     "multiple", ""],
                ["notify",      "optional",     "multiple", "inverse key"],
                ["abuse-mailbox","optional",    "multiple", "inverse key"],
                ["mnt-by",      "mandatory",    "multiple", "inverse key"],
                ["changed",     "mandatory",    "multiple", ""],
                ["source",      "mandatory",    "single",   ""],
        ]
        template.getAttributeDescription("country") =~ /AP/
        template.getAttributeDescription("country") =~ /EU/
        template.getAttributeDescription("admin-c") =~ /-AP/
        template.getAttributeDescription("tech-c") =~ /-AP/
        template.getAttributeDescription("nic-hdl") =~ /-AP/
        template.getAttributeDescription("source") =~ /APNIC/
    }

    def "route-set"() {
        when:
        def template = new TemplateObject("route-set")

        then:
        template.description =~ /route-set/
        template.basicTemplate == [
                ["route-set",   "mandatory",    "single",   "primary/lookup key"],
                ["descr",       "mandatory",    "multiple", ""],
                ["members",     "optional",     "multiple", ""],
                ["mp-members",  "optional",     "multiple", ""],
                ["mbrs-by-ref", "optional",     "multiple", "inverse key"],
                ["remarks",     "optional",     "multiple", ""],
                ["org",         "optional",     "multiple", "inverse key"],
                ["tech-c",      "mandatory",    "multiple", "inverse key"],
                ["admin-c",     "mandatory",    "multiple", "inverse key"],
                ["notify",      "optional",     "multiple", "inverse key"],
                ["mnt-by",      "mandatory",    "multiple", "inverse key"],
                ["mnt-lower",   "optional",     "multiple", "inverse key"],
                ["changed",     "mandatory",    "multiple", ""],
                ["source",      "mandatory",    "single",   ""],
        ]
        template.getAttributeDescription("tech-c") =~ /-AP/
        template.getAttributeDescription("admin-c") =~ /-AP/
        template.getAttributeDescription("source") =~ /APNIC/
    }

    def "route"() {
      when:
        def template = new TemplateObject("route")

      then:
        template.description =~ /route/
        template.basicTemplate == [
                ["route",       "mandatory",    "single",   "primary/lookup key"],
                ["descr",       "mandatory",    "multiple", ""],
                ["origin",      "mandatory",    "single",   "primary/inverse key"],
                ["holes",       "optional",     "multiple", ""],
                ["country",     "optional",     "single",   ""],
                ["org",         "optional",     "multiple", "inverse key"],
                ["member-of",   "optional",     "multiple", "inverse key"],
                ["inject",      "optional",     "multiple", ""],
                ["aggr-mtd",    "optional",     "single",   ""],
                ["aggr-bndry",  "optional",     "single",   ""],
                ["export-comps","optional",     "single",   ""],
                ["components",  "optional",     "single",   ""],
                ["remarks",     "optional",     "multiple", ""],
                ["notify",      "optional",     "multiple", "inverse key"],
                ["mnt-lower",   "optional",     "multiple", "inverse key"],
                ["mnt-routes",  "optional",     "multiple", "inverse key"],
                ["mnt-by",      "mandatory",    "multiple", "inverse key"],
                ["changed",     "mandatory",    "multiple", ""],
                ["source",      "mandatory",    "single",   ""],
        ]
        template.getAttributeDescription("country") =~ /AP/
        template.getAttributeDescription("country") =~ /EU/
        template.getAttributeDescription("source") =~ /APNIC/
    }

    def "route6"() {
        when:
        def template = new TemplateObject("route6")

        then:
        template.description =~ /route6/
        template.basicTemplate == [
                ["route6",      "mandatory",    "single",   "primary/lookup key"],
                ["descr",       "mandatory",    "multiple", ""],
                ["origin",      "mandatory",    "single",   "primary/inverse key"],
                ["country",     "optional",     "single",   ""],
                ["holes",       "optional",     "multiple", ""],
                ["org",         "optional",     "multiple", "inverse key"],
                ["member-of",   "optional",     "multiple", "inverse key"],
                ["inject",      "optional",     "multiple", ""],
                ["aggr-mtd",    "optional",     "single",   ""],
                ["aggr-bndry",  "optional",     "single",   ""],
                ["export-comps","optional",     "single",   ""],
                ["components",  "optional",     "single",   ""],
                ["remarks",     "optional",     "multiple", ""],
                ["notify",      "optional",     "multiple", "inverse key"],
                ["mnt-lower",   "optional",     "multiple", "inverse key"],
                ["mnt-routes",  "optional",     "multiple", "inverse key"],
                ["mnt-by",      "mandatory",    "multiple", "inverse key"],
                ["changed",     "mandatory",    "multiple", ""],
                ["source",      "mandatory",    "single",   ""],
        ]
        template.getAttributeDescription("country") =~ /AP/
        template.getAttributeDescription("country") =~ /EU/
        template.getAttributeDescription("source") =~ /APNIC/
    }

    def "rtr-set"() {
      when:
        def template = new TemplateObject("rtr-set")

      then:
        template.description =~ /rtr-set/
        template.basicTemplate == [
                ["rtr-set",     "mandatory",    "single",   "primary/lookup key"],
                ["descr",       "mandatory",    "multiple", ""],
                ["members",     "optional",     "multiple", ""],
                ["mp-members",  "optional",     "multiple", ""],
                ["mbrs-by-ref", "optional",     "multiple", "inverse key"],
                ["remarks",     "optional",     "multiple", ""],
                ["org",         "optional",     "multiple", "inverse key"],
                ["tech-c",      "mandatory",    "multiple", "inverse key"],
                ["admin-c",     "mandatory",    "multiple", "inverse key"],
                ["notify",      "optional",     "multiple", "inverse key"],
                ["mnt-by",      "mandatory",    "multiple", "inverse key"],
                ["mnt-lower",   "optional",     "multiple", "inverse key"],
                ["changed",     "mandatory",    "multiple", ""],
                ["source",      "mandatory",    "single",   ""],
        ]
        template.getAttributeDescription("tech-c") =~ /-AP/
        template.getAttributeDescription("admin-c") =~ /-AP/
        template.getAttributeDescription("source") =~ /APNIC/
    }
}
