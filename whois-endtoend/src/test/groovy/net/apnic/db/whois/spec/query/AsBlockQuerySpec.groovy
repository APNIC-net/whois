package net.apnic.db.whois.spec.query

import net.apnic.db.whois.spec.BaseSpec

class AsBlockQuerySpec extends BaseSpec {
    @Override
    Map<String, String> getTransients() {
        [
                "AS40000-AS49999": """\
                    as-block:   AS40000 - AS49999
                    descr:      A parent AS block
                    admin-c:    HM1-AP
                    tech-c:     NO1-AP
                    mnt-by:     APNIC-HM
                    changed:    testdbm@apnic.net 20130101
                    source:     TEST
                    """,
                "AS44500-AS46500": """\
                    as-block:   AS44500 - AS46500
                    descr:      A child AS block
                    admin-c:    HM1-AP
                    tech-c:     NO1-AP
                    mnt-by:     TEST-USER-MNT
                    changed:    testdbm@apnic.net 20130101
                    source:     TEST
                    """,
                "AS45000": """\
                    aut-num:    AS45000
                    as-name:    AS-TEST
                    descr:      Testing aut-num
                    country:    AU
                    admin-c:    HM1-AP
                    tech-c:     NO1-AP
                    mnt-by:     TEST-USER-MNT
                    mnt-irt:    IRT-USER
                    changed:    testdbm@apnic.net 20130101
                    source:     TEST
                    """,
        ]
    }

    def "as-block query"() {
      given:
        databaseHelper.addObject(getTransient("AS40000-AS49999"))
        databaseHelper.addObject(getTransient("AS44500-AS46500"))
        def response = query("-r AS44500 - AS46500")

      expect:
        response =~ /as-block:\s*AS40000 - AS49999/
        response =~ /as-block:\s*AS44500 - AS46500/
    }

    def "aut-num with parent as-blocks query"() {
      given:
        databaseHelper.addObject(getTransient("AS40000-AS49999"))
        databaseHelper.addObject(getTransient("AS44500-AS46500"))
        databaseHelper.addObject(getTransient("AS45000"))
        def response = query("-r AS45000")

      expect:
        response =~ /as-block:\s*AS40000 - AS49999/
        response =~ /as-block:\s*AS44500 - AS46500/
        response =~ /aut-num:\s*AS45000/
    }
}
