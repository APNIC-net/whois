package net.apnic.db.whois.spec.update

import net.apnic.db.whois.spec.BaseSpec
import spec.domain.Message
import spock.lang.Ignore

class DomainAuthSpecNotYet extends BaseSpec {
    @Override
    Map<String,String> getTransients() {
        [
                "INET4": """\
                    inetnum:    193.0.0.0 - 193.255.255.255
                    netname:    TEST-NET-NAME
                    descr:      TEST network
                    country:    AU
                    admin-c:    TP1-TEST
                    tech-c:     TP1-TEST
                    status:     ALLOCATED PORTABLE
                    mnt-by:     TEST-USER-MNT
                    mnt-irt:    IRT-USER
                    changed:    testdbm@apnic.net 20130101
                    source:     TEST
                    """
        ]
    }

    @Ignore
    def "create domain, without ds-rdata, via mail"() {
        given:
            syncUpdate(getTransient("INET4") + passwords("user", "irt"))
        when:
            def message = send new Message(
                    subject: "Make this",
                    body: """\
                        domain:     193.in-addr.arpa
                        descr:      reverse domain
                        admin-c:    TP1-AP
                        tech-c:     TP1-AP
                        zone-c:     TP1-AP
                        mnt-by:     TEST-USER-MNT
                        changed:    testdbm@apnic.net 20130101
                        source:     TEST

                        password:   user
                        """.stripIndent()
            )
        then:
            1 == 1
    }
}
