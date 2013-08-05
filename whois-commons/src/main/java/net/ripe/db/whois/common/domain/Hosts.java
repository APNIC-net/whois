package net.ripe.db.whois.common.domain;

import com.google.common.collect.Lists;
import com.google.common.collect.Maps;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public enum Hosts {
    WHOIS1("whoisv4-node1.apnic.net"),
    WHOIS2("whoisv4-node2.apnic.net"),
    WHOIS3("whoisv4-node3.apnic.net"),
    WHOIS4("whoisv4-node4.apnic.net"),
    UNDEFINED("");

    private static final Map<Hosts, List<Hosts>> CLUSTER_MAP = Maps.newEnumMap(Hosts.class);

    static {
        addHosts(Lists.newArrayList(WHOIS1, WHOIS2, WHOIS3, WHOIS4));
    }

    static void addHosts(final List<Hosts> hosts) {
        for (final Hosts host : hosts) {
            CLUSTER_MAP.put(host, hosts);
        }
    }

    private final String hostName;

    private Hosts(final String hostName) {
        this.hostName = hostName;
    }

    public String getHostName() {
        return hostName;
    }

    public List<Hosts> getClusterMembers() {
        final List<Hosts> hosts = CLUSTER_MAP.get(this);
        if (hosts == null) {
            return Collections.emptyList();
        }

        return hosts;
    }

    public static Hosts getLocalHost() {
        try {
            return getHost(InetAddress.getLocalHost().getHostName());
        } catch (UnknownHostException e) {
            return Hosts.UNDEFINED;
        }
    }

    public static Hosts getHost(final String hostname) {
        for (final Hosts host : Hosts.values()) {
            if (host.hostName.equals(hostname)) {
                return host;
            }
        }

        return Hosts.UNDEFINED;
    }
}
