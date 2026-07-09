package com.dpi.engine;

import java.util.ArrayDeque;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

/**
 * A bounded, blocking, thread-safe queue -- the Java equivalent of the
 * C++ {@code TSQueue<T>} described in the original README: a mutex plus
 * two condition variables (not-empty / not-full) guarding a plain queue.
 *
 * push() blocks while the queue is full; pop() blocks while it is empty.
 * A sentinel-free {@code close()} lets the producer signal "no more items"
 * so waiting consumers can wake up and exit instead of blocking forever.
 */
public final class ThreadSafeQueue<T> {

    private final ArrayDeque<T> queue = new ArrayDeque<>();
    private final int capacity;
    private final ReentrantLock lock = new ReentrantLock();
    private final Condition notEmpty = lock.newCondition();
    private final Condition notFull = lock.newCondition();
    private volatile boolean closed = false;

    public ThreadSafeQueue() {
        this(100_000);
    }

    public ThreadSafeQueue(int capacity) {
        this.capacity = capacity;
    }

    /** Producer adds an item, blocking if the queue is currently full. */
    public void push(T item) throws InterruptedException {
        lock.lock();
        try {
            while (queue.size() >= capacity && !closed) {
                notFull.await();
            }
            queue.addLast(item);
            notEmpty.signal();
        } finally {
            lock.unlock();
        }
    }

    /**
     * Consumer waits until an item is available, then returns it.
     * @return the next item, or {@code null} if the queue was closed and drained.
     */
    public T pop() throws InterruptedException {
        lock.lock();
        try {
            while (queue.isEmpty() && !closed) {
                notEmpty.await();
            }
            if (queue.isEmpty()) {
                return null; // closed and drained
            }
            T item = queue.removeFirst();
            notFull.signal();
            return item;
        } finally {
            lock.unlock();
        }
    }

    public int size() {
        lock.lock();
        try {
            return queue.size();
        } finally {
            lock.unlock();
        }
    }

    public boolean isEmpty() {
        return size() == 0;
    }

    /** Signals that no more items will be pushed; wakes all waiting consumers. */
    public void close() {
        lock.lock();
        try {
            closed = true;
            notEmpty.signalAll();
            notFull.signalAll();
        } finally {
            lock.unlock();
        }
    }

    public boolean isClosed() {
        return closed;
    }
}
