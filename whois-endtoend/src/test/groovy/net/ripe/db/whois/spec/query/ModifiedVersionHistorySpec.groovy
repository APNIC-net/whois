package net.ripe.db.whois.spec.query

import net.ripe.db.whois.spec.BaseSpec
import net.ripe.db.whois.spec.BasicFixtures
import spec.domain.AckResponse

class ModifiedVersionHistorySpec extends BaseSpec {

    @Override
    Map<String, String> getBasicFixtures() {
        return BasicFixtures.permanentFixtures
    }

    @Override
    Map<String, String> getFixtures() {
        [
            "ORG-FO1": """\
                organisation:    ORG-FO1-TEST
                org-type:        other
                org-name:        First Org
                org:             ORG-FO1-TEST
                address:         RIPE NCC
                                 Singel 258
                                 1016 AB Amsterdam
                                 Netherlands
                e-mail:          dbtest@ripe.net
                mnt-ref:         owner3-mnt
                mnt-by:          owner2-mnt
                changed:         denis@ripe.net 20121016
                source:          TEST
                """,
            "OLDMNTNER": """\
                mntner:         OLD-MNT
                descr:          description
                admin-c:        TP1-TEST
                mnt-by:         OLD-MNT
                referral-by:    OLD-MNT
                upd-to:         updto_cre@ripe.net
                auth:           MD5-PW \$1\$fU9ZMQN9\$QQtm3kRqZXWAuLpeOiLN7. # update
                auth:           CRYPT-PW QQtm3kRqZXWAu
                changed:        dbtest@ripe.net 20120707
                source:         TEST
                """
        ]
    }

    @Override
    Map<String, String> getTransients() {
        [
            "RIR-ALLOC-20": """\
                inet6num:     2001::/20
                netname:      EU-ZZ-2001-0600
                descr:        European Regional Registry
                country:      EU
                org:          ORG-LIR1-TEST
                admin-c:      TP1-TEST
                tech-c:       TP1-TEST
                mnt-by:       RIPE-NCC-HM-MNT
                mnt-lower:    RIPE-NCC-HM-MNT
                status:       ALLOCATED-BY-RIR
                changed:      dbtest@ripe.net 20130101
                source:       TEST
                """,
            "ALLOC-PA": """\
                inetnum:      192.168.0.0 - 192.169.255.255
                netname:      TEST-NET-NAME
                descr:        TEST network
                country:      NL
                org:          ORG-LIR1-TEST
                admin-c:      TP1-TEST
                tech-c:       TP1-TEST
                status:       ALLOCATED PA
                mnt-by:       RIPE-NCC-HM-MNT
                mnt-lower:    LIR-MNT
                changed:      dbtest@ripe.net 20020101
                source:       TEST
                """,
            "ASS-END": """\
                inetnum:      192.168.200.0 - 192.168.200.255
                netname:      RIPE-NET1
                descr:        /24 assigned
                country:      NL
                admin-c:      TP1-TEST
                tech-c:       TP1-TEST
                status:       ASSIGNED PA
                mnt-by:       END-USER-MNT
                changed:      dbtest@ripe.net 20020101
                source:       TEST
                """,
            "PN-FF": """\
                person:  fred fred
                address: St James Street
                address: Burnley
                address: UK
                phone:   +44 282 420469
                nic-hdl: ff1-TEST
                mnt-by:  OWNER-MNT
                changed: dbtest@ripe.net 20120101
                source:  TEST
                """,
            "RL-FR": """\
                role:    First Role
                address: St James Street
                address: Burnley
                address: UK
                e-mail:  dbtest@ripe.net
                nic-hdl: FR1-TEST
                mnt-by:  OWNER-MNT
                changed: dbtest@ripe.net 20121016
                source:  TEST
                """,
            "SELF-MNT": """\
                mntner:  SELF-MNT
                descr:   description
                admin-c: TP1-TEST
                mnt-by:  SELF-MNT
                referral-by: SELF-MNT
                upd-to:  updto_cre@ripe.net
                auth:    MD5-PW \$1\$fU9ZMQN9\$QQtm3kRqZXWAuLpeOiLN7. # update
                changed: dbtest@ripe.net 20120707
                source:  TEST
                """,
            "PAUL": """\
                mntner:  PAUL
                descr:   description
                admin-c: TP1-TEST
                mnt-by:  PAUL
                referral-by: PAUL
                upd-to:  updto_cre@ripe.net
                auth:    MD5-PW \$1\$fU9ZMQN9\$QQtm3kRqZXWAuLpeOiLN7. # update
                changed: dbtest@ripe.net 20120707
                source:  TEST
                """,
            "AS1000": """\
                aut-num:     AS1000
                as-name:     TEST-AS
                descr:       Testing Authorisation code
                admin-c:     TP1-TEST
                tech-c:      TP1-TEST
                mnt-by:      LIR-MNT
                changed:     dbtest@ripe.net
                source:      TEST
                """,
            "AS2000": """\
                aut-num:     AS2000
                as-name:     TEST-AS
                descr:       Testing Authorisation code
                admin-c:     TP1-TEST
                tech-c:      TP1-TEST
                mnt-by:      LIR-MNT
                changed:     dbtest@ripe.net
                source:      TEST
                """,
        ]
    }

    def "query --show-version for 2 exact matching route and -k, 2 & 3 versions exist"() {
        given:
        syncUpdate(getTransient("ASS-END") + "override: override1")
        syncUpdate(getTransient("AS1000") + "override: override1")
        syncUpdate(getTransient("AS2000") + "override: override1")

        expect:
        // "ASS-END"
        queryObject("-rBG -T inetnum 192.168.200.0 - 192.168.200.255", "inetnum", "192.168.200.0 - 192.168.200.255")
        // "AS1000"
        queryObject("-rBG -T aut-num AS1000", "aut-num", "AS1000")
        // "AS2000"
        queryObject("-rBG -T aut-num AS2000", "aut-num", "AS2000")

        when:
        def message = syncUpdate("""\
                route:          192.168.200.0/24
                descr:          Route
                origin:         AS1000
                mnt-by:         LIR-MNT
                changed:        noreply@ripe.net 20120101
                source:         TEST
                override:  override1

                route:          192.168.200.0/24
                descr:          Route
                origin:         AS1000
                mnt-by:         LIR-MNT
                remarks:        version 2
                changed:        noreply@ripe.net 20120101
                source:         TEST
                override:  override1

                route:          192.168.200.0/24
                descr:          Route
                origin:         AS2000
                mnt-by:         LIR-MNT
                changed:        noreply@ripe.net 20120101
                source:         TEST
                override:  override1

                route:          192.168.200.0/24
                descr:          Route
                origin:         AS2000
                mnt-by:         LIR-MNT
                remarks:        version 2
                changed:        noreply@ripe.net 20120101
                source:         TEST
                override:  override1

                route:          192.168.200.0/24
                descr:          Route
                origin:         AS2000
                mnt-by:         LIR-MNT
                remarks:        version 3
                changed:        noreply@ripe.net 20120101
                source:         TEST
                override:  override1

                """.stripIndent()
        )

        then:
        def ack = new AckResponse("", message)

        ack.summary.nrFound == 5
        ack.summary.assertSuccess(5, 2, 3, 0, 0)
        ack.summary.assertErrors(0, 0, 0, 0)

        ack.countErrorWarnInfo(0, 0, 5)
        ack.successes.any { it.operation == "Create" && it.key == "[route] 192.168.200.0/24AS1000" }
        ack.successes.any { it.operation == "Modify" && it.key == "[route] 192.168.200.0/24AS1000" }

        query_object_matches("-GBr -T route 192.168.200.0/24", "route", "192.168.200.0/24", "version 2")
        query_object_matches("-GBr -T route 192.168.200.0/24", "route", "192.168.200.0/24", "version 3")

        // -k
        queryLineMatches("-k --show-version 2 192.168.200.0/24AS1000\n\n--show-version 2 192.168.200.0/24AS2000\n\n--show-version 3 192.168.200.0/24AS2000\n\n-k", "^% Version 2 \\(current version\\) of object \"192.168.200.0/24AS1000\"")
        queryLineMatches("-k --show-version 2 192.168.200.0/24AS1000\n\n--show-version 2 192.168.200.0/24AS2000\n\n--show-version 3 192.168.200.0/24AS2000\n\n-k", "^% This version was a UPDATE operation on ")
        queryLineMatches("-k --show-version 2 192.168.200.0/24AS1000\n\n--show-version 2 192.168.200.0/24AS2000\n\n--show-version 3 192.168.200.0/24AS2000\n\n-k", "^remarks:\\s*version 2")

        queryLineMatches("-k --show-version 2 192.168.200.0/24AS1000\n\n--show-version 2 192.168.200.0/24AS2000\n\n--show-version 3 192.168.200.0/24AS2000\n\n-k", "^% Version 2 of object \"192.168.200.0/24AS2000\"")
        queryLineMatches("-k --show-version 2 192.168.200.0/24AS1000\n\n--show-version 2 192.168.200.0/24AS2000\n\n--show-version 3 192.168.200.0/24AS2000\n\n-k", "^% This version was a UPDATE operation on ")
        queryLineMatches("-k --show-version 2 192.168.200.0/24AS1000\n\n--show-version 2 192.168.200.0/24AS2000\n\n--show-version 3 192.168.200.0/24AS2000\n\n-k", "^remarks:\\s*version 2")

        queryLineMatches("-k --show-version 2 192.168.200.0/24AS1000\n\n--show-version 2 192.168.200.0/24AS2000\n\n--show-version 3 192.168.200.0/24AS2000\n\n-k", "^% Version 3 \\(current version\\) of object \"192.168.200.0/24AS2000\"")
        queryLineMatches("-k --show-version 2 192.168.200.0/24AS1000\n\n--show-version 2 192.168.200.0/24AS2000\n\n--show-version 3 192.168.200.0/24AS2000\n\n-k", "^% This version was a UPDATE operation on ")
        queryLineMatches("-k --show-version 2 192.168.200.0/24AS1000\n\n--show-version 2 192.168.200.0/24AS2000\n\n--show-version 3 192.168.200.0/24AS2000\n\n-k", "^remarks:\\s*version 3")

        // --persistent-connection
        queryLineMatches("--persistent-connection --show-version 2 192.168.200.0/24AS1000\n\n--show-version 2 192.168.200.0/24AS2000\n\n--show-version 3 192.168.200.0/24AS2000\n\n--persistent-connection", "^% Version 2 \\(current version\\) of object \"192.168.200.0/24AS1000\"")
        queryLineMatches("--persistent-connection --show-version 2 192.168.200.0/24AS1000\n\n--show-version 2 192.168.200.0/24AS2000\n\n--show-version 3 192.168.200.0/24AS2000\n\n--persistent-connection", "^% This version was a UPDATE operation on ")
        queryLineMatches("--persistent-connection --show-version 2 192.168.200.0/24AS1000\n\n--show-version 2 192.168.200.0/24AS2000\n\n--show-version 3 192.168.200.0/24AS2000\n\n--persistent-connection", "^remarks:\\s*version 2")

        queryLineMatches("--persistent-connection --show-version 2 192.168.200.0/24AS1000\n\n--show-version 2 192.168.200.0/24AS2000\n\n--show-version 3 192.168.200.0/24AS2000\n\n--persistent-connection", "^% Version 2 of object \"192.168.200.0/24AS2000\"")
        queryLineMatches("--persistent-connection --show-version 2 192.168.200.0/24AS1000\n\n--show-version 2 192.168.200.0/24AS2000\n\n--show-version 3 192.168.200.0/24AS2000\n\n--persistent-connection", "^% This version was a UPDATE operation on ")
        queryLineMatches("--persistent-connection --show-version 2 192.168.200.0/24AS1000\n\n--show-version 2 192.168.200.0/24AS2000\n\n--show-version 3 192.168.200.0/24AS2000\n\n--persistent-connection", "^remarks:\\s*version 2")

        queryLineMatches("--persistent-connection --show-version 2 192.168.200.0/24AS1000\n\n--show-version 2 192.168.200.0/24AS2000\n\n--show-version 3 192.168.200.0/24AS2000\n\n--persistent-connection", "^% Version 3 \\(current version\\) of object \"192.168.200.0/24AS2000\"")
        queryLineMatches("--persistent-connection --show-version 2 192.168.200.0/24AS1000\n\n--show-version 2 192.168.200.0/24AS2000\n\n--show-version 3 192.168.200.0/24AS2000\n\n--persistent-connection", "^% This version was a UPDATE operation on ")
        queryLineMatches("--persistent-connection --show-version 2 192.168.200.0/24AS1000\n\n--show-version 2 192.168.200.0/24AS2000\n\n--show-version 3 192.168.200.0/24AS2000\n\n--persistent-connection", "^remarks:\\s*version 3")

    }


}
