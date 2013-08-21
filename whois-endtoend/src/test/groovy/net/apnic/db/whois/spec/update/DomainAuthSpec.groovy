package net.apnic.db.whois.spec.update

import net.apnic.db.whois.spec.BaseSpec
import spec.domain.AckResponse
import spec.domain.Message
import spock.lang.Ignore

class DomainAuthSpec extends BaseSpec {
    @Override
    Map<String, String> getFixtures() {
        [
                "INET4": """\
                    inetnum:    193.0.0.0 - 193.255.255.255
                    netname:    TEST-NET-NAME
                    descr:      TEST network
                    country:    AU
                    admin-c:    TP1-AP
                    tech-c:     TP1-AP
                    status:     ALLOCATED NON-PORTABLE
                    mnt-by:     TEST-USER-MNT
                    mnt-irt:    IRT-USER
                    changed:    testdbm@apnic.net 20130101
                    source:     TEST
                    """
        ]
    }

    @Override
    Map<String, String> getTransients() {
        [
                "NEW-NO-RDATA": """\
                    domain:     1.1.193.in-addr.arpa
                    descr:      reverse domain
                    admin-c:    TP1-AP
                    tech-c:     TP1-AP
                    zone-c:     TP1-AP
                    mnt-by:     TEST-USER-MNT
                    changed:    testdbm@apnic.net 20130101
                    source:     TEST
                    """,
                "NEW-WITH-RDATA": """\
                    domain:     2.1.193.in-addr.arpa
                    descr:      reverse domain
                    admin-c:    TP1-AP
                    tech-c:     TP1-AP
                    zone-c:     TP1-AP
                    ds-rdata:   1 2 1 0123456789ABCDEF0123456789ABCDEF01234567
                    mnt-by:     TEST-USER-MNT
                    changed:    testdbm@apnic.net 20130101
                    source:     TEST
                    """,
                "EXISTING-NO-RDATA": """\
                    domain:     1.2.193.in-addr.arpa
                    descr:      Existing domain
                    admin-c:    TP1-AP
                    tech-c:     TP1-AP
                    zone-c:     TP1-AP
                    mnt-by:     TEST-USER-MNT
                    changed:    testdbm@apnic.net 20130101
                    source:     TEST
                    """,
                "EXISTING-WITH-RDATA": """\
                    domain:     1.2.193.in-addr.arpa
                    descr:      Existing domain
                    admin-c:    TP1-AP
                    tech-c:     TP1-AP
                    zone-c:     TP1-AP
                    ds-rdata:   1 2 1 0123456789ABCDEF0123456789ABCDEF01234567
                    mnt-by:     TEST-USER-MNT
                    changed:    testdbm@apnic.net 20130101
                    source:     TEST
                    """,
                "UPDATE-NO-RDATA": """\
                    domain:     1.2.193.in-addr.arpa
                    descr:      Replacement domain
                    admin-c:    TP1-AP
                    tech-c:     TP1-AP
                    zone-c:     TP1-AP
                    mnt-by:     TEST-USER-MNT
                    changed:    testdbm@apnic.net 20130202
                    changed:    testdbm@apnic.net 20130101
                    source:     TEST
                    """,
                "UPDATE-ONE-RDATA": """\
                    domain:     1.2.193.in-addr.arpa
                    descr:      Replacement domain
                    admin-c:    TP1-AP
                    tech-c:     TP1-AP
                    zone-c:     TP1-AP
                    ds-rdata:   1 2 1 0123456789ABCDEF0123456789ABCDEF01234567
                    mnt-by:     TEST-USER-MNT
                    changed:    testdbm@apnic.net 20130202
                    changed:    testdbm@apnic.net 20130101
                    source:     TEST
                    """,
                "UPDATE-TWO-RDATA": """\
                    domain:     1.2.193.in-addr.arpa
                    descr:      Replacement domain
                    admin-c:    TP1-AP
                    tech-c:     TP1-AP
                    zone-c:     TP1-AP
                    ds-rdata:   1 2 1 0123456789ABCDEF0123456789ABCDEF01234567
                    ds-rdata:   2 1 1 ABCDEF0123456789ABCDEF0123456789ABCDEF01
                    mnt-by:     TEST-USER-MNT
                    changed:    testdbm@apnic.net 20130202
                    changed:    testdbm@apnic.net 20130101
                    source:     TEST
                    """,
                "UPDATE-CHANGE-RDATA": """\
                    domain:     1.2.193.in-addr.arpa
                    descr:      Replacement domain
                    admin-c:    TP1-AP
                    tech-c:     TP1-AP
                    zone-c:     TP1-AP
                    ds-rdata:   1 2 1 ABCDEF0123456789ABCDEF0123456789ABCDEF01
                    mnt-by:     TEST-USER-MNT
                    changed:    testdbm@apnic.net 20130202
                    changed:    testdbm@apnic.net 20130101
                    source:     TEST
                    """,
                "DELETE-NO-RDATA": """\
                    domain:     1.2.193.in-addr.arpa
                    descr:      Existing domain
                    admin-c:    TP1-AP
                    tech-c:     TP1-AP
                    zone-c:     TP1-AP
                    mnt-by:     TEST-USER-MNT
                    changed:    testdbm@apnic.net 20130101
                    source:     TEST
                    delete:     testing
                    """,
                "DELETE-WITH-RDATA": """\
                    domain:     1.2.193.in-addr.arpa
                    descr:      Existing domain
                    admin-c:    TP1-AP
                    tech-c:     TP1-AP
                    zone-c:     TP1-AP
                    ds-rdata:   1 2 1 0123456789ABCDEF0123456789ABCDEF01234567
                    mnt-by:     TEST-USER-MNT
                    changed:    testdbm@apnic.net 20130101
                    source:     TEST
                    delete:     testing
                    """,
        ]
    }

    def "create domain, without ds-rdata, via mail"() {
      when:
        def message = send new Message(
                subject: "Make this",
                body: getTransient("NEW-NO-RDATA") + passwords("user"),
        )

      then:
        def ack = ackFor(message)
        ack.subject == "SUCCESS: Make this"
    }

    def "create domain, with ds-rdata, via mail"() {
      when:
        def message = send new Message(
                subject: "new domain",
                body: getTransient("NEW-WITH-RDATA") + passwords("user"),
        )

      then:
        def ack = ackFor(message)
        ack.subject == "FAILED: new domain"
        ack.contents =~ /\*\*\*Error:   Attribute ds-rdata cannot be modified via email update/
    }

    def "update domain, no ds-rdata, via mail"() {
      given:
        syncUpdate(getTransient("EXISTING-NO-RDATA") + passwords("user"))

      when:
        def message = send new Message(
                subject: "object change",
                body: getTransient("UPDATE-NO-RDATA") + passwords("user"),
        )

      then:
        def ack = ackFor(message)
        ack.subject == "SUCCESS: object change"
    }

    def "update domain, no ds-rdata change, via mail"() {
      given:
        syncUpdate(getTransient("EXISTING-WITH-RDATA") + passwords("user"))

      when:
        def message = send new Message(
                subject: "trivial change",
                body:  getTransient("UPDATE-ONE-RDATA") + passwords("user"),
        )

      then:
        def ack = ackFor(message)
        ack.subject == "SUCCESS: trivial change"
    }

    def "update domain, change ds-rdata, via mail"() {
      given:
        syncUpdate(getTransient("EXISTING-WITH-RDATA") + passwords("user"))

      when:
        def message = send new Message(
                subject: "security change",
                body:  getTransient("UPDATE-CHANGE-RDATA")+passwords("user"),
        )

      then:
        def ack = ackFor(message)
        ack.subject == "FAILED: security change"
        ack.contents =~ /\*\*\*Error:   Attribute ds-rdata cannot be modified via email update/
    }

    def "update domain, add ds-rdata, via mail"() {
      given:
        syncUpdate(getTransient("EXISTING-NO-RDATA") + passwords("user"))

      when:
        def message = send new Message(
                subject: "key setup",
                body: getTransient("UPDATE-ONE-RDATA") + passwords("user")
        )

      then:
        def ack = ackFor(message)
        ack.subject == "FAILED: key setup"
        ack.contents =~ /\*\*\*Error:   Attribute ds-rdata cannot be modified via email update/
    }

    def "update domain, add extra ds-rdata, via mail"() {
      given:
        syncUpdate(getTransient("EXISTING-WITH-RDATA") + passwords("user"))

      when:
        def message = send new Message(
                subject: "extra key",
                body: getTransient("UPDATE-TWO-RDATA") + passwords("user")
        )

      then:
        def ack = ackFor(message)
        ack.subject == "FAILED: extra key"
        ack.contents =~ /\*\*\*Error:   Attribute ds-rdata cannot be modified via email update/
    }

    def "update domain, remove ds-rdata, via mail"() {
      given:
        syncUpdate(getTransient("EXISTING-WITH-RDATA") + passwords("user"))

      when:
        def message = send new Message(
                subject: "no more key",
                body: getTransient("UPDATE-NO-RDATA") + passwords("user")
        )

      then:
        def ack = ackFor(message)
        ack.subject == "FAILED: no more key"
        ack.contents =~ /\*\*\*Error:   Attribute ds-rdata cannot be modified via email update/
    }

    def "delete domain, no ds-rdata, via mail"() {
      given:
        syncUpdate(getTransient("EXISTING-NO-RDATA") + passwords("user"))

      when:
        def message = send new Message(
                subject: "delete domain",
                body: getTransient("DELETE-NO-RDATA") + passwords("user")
        )

      then:
        def ack = ackFor(message)
        ack.subject == "SUCCESS: delete domain"
    }

    def "delete domain, with ds-rdata, via mail"() {
      given:
        syncUpdate(getTransient("EXISTING-WITH-RDATA") + passwords("user"))

      when:
        def message = send new Message(
                subject: "delete domain",
                body: getTransient("DELETE-WITH-RDATA") + passwords("user")
        )

      then:
        def ack = ackFor(message)
        ack.subject == "FAILED: delete domain"
        ack.contents =~ /\*\*\*Error:   Attribute ds-rdata cannot be modified via email update/
    }
}
