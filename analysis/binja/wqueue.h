#ifndef WQUEUE_H
#define WQUEUE_H
#include <pthread.h>
#include <list>
// From https://vichargrave.github.io/programming/multithreaded-work-queue-in-cpp/
using namespace std;

template <typename T> class wqueue
{
    list<T>   m_queue;
    pthread_mutex_t m_mutex;
    pthread_cond_t  m_condv;

public:
    wqueue() {
        pthread_mutex_init(&m_mutex, NULL);
        pthread_cond_init(&m_condv, NULL);
    }
    ~wqueue() {
        printf("Mutex destroyed for some reason\n");
        pthread_mutex_destroy(&m_mutex);
        pthread_cond_destroy(&m_condv);
    }
    void add(T item) {
        //pthread_mutex_lock(&m_mutex);
        m_queue.push_back(item);
        //pthread_cond_signal(&m_condv);
        //pthread_mutex_unlock(&m_mutex);
    }
    optional<T> remove() {
        pthread_mutex_lock(&m_mutex);
        if (m_queue.size() == 0) {
            pthread_mutex_unlock(&m_mutex);
            return std::nullopt;
        }
        T item = m_queue.front();
        m_queue.pop_front();
        pthread_mutex_unlock(&m_mutex);
        return item;
    }
    int size() {
        pthread_mutex_lock(&m_mutex);
        int size = m_queue.size();
        pthread_mutex_unlock(&m_mutex);
        return size;
    }
};
#endif
