#include <cstdio>
#include <string>
#include <vector>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <assert.h>
#include <math.h>

using namespace std;

const int RPT = 100;
const char* TMP_FILENAME = "tmp_file";

class AbstractTest {
    public:
        virtual void test() = 0;
        virtual string name() = 0;
        double current_time() {
            struct timeval tv;
            gettimeofday(&tv, NULL);
            return (double)tv.tv_sec + tv.tv_usec/1000000.0l;
        }

        void run(int how_many) {
            vector<double> times;
            double mean = 0;
            double start, end;
            double variance = 0;
            printf("[ %30s ] ", name().c_str());
            for (int i = 0; i < how_many; ++i) {
                start = current_time();
                test();
                end = current_time();
                mean += end - start;
                times.push_back(end-start);
            }
            mean /= how_many;
            for (int i = 0; i < times.size(); ++i)
                variance += pow(times[i] - mean, 2);
            variance = variance/how_many;

            printf(" mean: %10.5lfs    variance: %10.5lf\n", mean, variance);
        }

};

class Test01: public AbstractTest {
    public:
        static const int BUF_LEN = 128;
        static const int IOV_N = 8;
        static const int ITERATIONS = 10;
        string name() { return "10xopen+writev+readv+close"; }
        void test() {
            char buffs[BUF_LEN * IOV_N];
            struct iovec vect[IOV_N];
            for (int i = 0; i < IOV_N; ++i) {
                vect[i].iov_base = (void*)(buffs + BUF_LEN*i);
                vect[i].iov_len = BUF_LEN;
            }

            for (int i = 0; i < ITERATIONS; ++i) {
                int fd;
                fd = creat(TMP_FILENAME, S_IRWXU);
                assert(fd > 0);
                assert(BUF_LEN*IOV_N == writev(fd, vect, IOV_N));
                assert(close(fd) == 0);

                fd = open(TMP_FILENAME, O_RDONLY);
                assert(fd > 0);
                assert(BUF_LEN*IOV_N == readv(fd, vect, IOV_N));
                assert(close(fd) == 0);
            }
            unlink(TMP_FILENAME);
        }
};

class Test02: public AbstractTest {
    public:
        static const int BUF_LEN = 32*32;
        static const int ITERATIONS = 10;
        string name() { return "10xopen+write+read+close"; }
        void test() {
            char buff[BUF_LEN];

            for (int i = 0; i < ITERATIONS; ++i) {
                int fd;
                fd = creat(TMP_FILENAME, S_IRWXU);
                assert(fd > 0);
                assert(BUF_LEN == write(fd, buff, BUF_LEN));
                assert(close(fd) == 0);

                fd = open(TMP_FILENAME, O_RDONLY);
                assert(fd > 0);
                assert(BUF_LEN == read(fd, buff, BUF_LEN));
                assert(close(fd) == 0);
            }
            unlink(TMP_FILENAME);
        }
};

int main() {
    {
        Test02 test;
        test.run(RPT);
    }
    {
        Test01 test;
        test.run(RPT);
    }
}
