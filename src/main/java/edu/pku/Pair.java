package edu.pku;

public class Pair<T> {
    private T first;

    public T getSecond() {
        return second;
    }

    public Pair<T> setSecond(T second) {
        this.second = second;
        return this;
    }

    private T second;

    public Pair(T frist, T second) {
        this.first = frist;
        this.second = second;
    }

    public T getFirst() {
        return first;
    }

    public Pair<T> setFirst(T frist) {
        this.first = frist;
        return this;
    }

    @Override public String toString() {
        final StringBuilder sb = new StringBuilder("Pair{");
        sb.append("first=").append(first);
        sb.append(", second=").append(second);
        sb.append('}');
        return sb.toString();
    }
}
