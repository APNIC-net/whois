
package net.ripe.db.whois.api.whois.rdap;

public class Pair<K, V>
{
    private K key;
    private V value;

    public K getKey()
    {
        return this.key;
    }

    public V getValue()
    {
        return this.value;
    }

    public Pair(K paramK, V paramV)
    {
        this.key = paramK;
        this.value = paramV;
    }

    public String toString()
    {
        return this.key + "=" + this.value;
    }

    public int hashCode()
    {
        return this.key.hashCode() * 13 + (this.value == null ? 0 : this.value.hashCode());
    }

    public boolean equals(Object paramObject)
    {
        if (this == paramObject) return true;
        if ((paramObject instanceof Pair)) {
            Pair localPair = (Pair)paramObject;
            if (this.key != null ? !this.key.equals(localPair.key) : localPair.key != null) return false;
            if (this.value != null ? !this.value.equals(localPair.value) : localPair.value != null) return false;
            return true;
        }
        return false;
    }
}
