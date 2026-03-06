#include <math.h>
#include <nmap.h>

float compute_rtt(struct timeval start, struct timeval end) {
    if (start.tv_sec == 0 || end.tv_sec == 0)
        return (0.f);
    return ((float)(end.tv_sec - start.tv_sec) * 1000.f +
            ((end.tv_usec / 1000.f) - (start.tv_usec / 1000.f)));
}

void update_host_rtt(struct host_stats *stat, float rtt) {
    float delta1, delta2;
    if (rtt > 0 && stat->min_rtt > rtt)
        stat->min_rtt = rtt;
    if (rtt > 0 && stat->max_rtt < rtt)
        stat->max_rtt = rtt;
    stat->total += 1;
    delta1 = rtt - stat->mean_rtt;
    stat->mean_rtt += delta1 / stat->total;
    delta2 = rtt - stat->mean_rtt;
    stat->M2 += delta1 * delta2;
}

/* static float get_stddev(t_ping_score *score) {
    if (score->total < 2)
        return (0.f);
    return (sqrt(score->M2 / (score->total - 1)));
}

void print_score(const char *hostname, t_ping_score *score) {
    printf("--- %s ping statistics ---\n"
           "%u packets transmmitted, %u packets received, %u%% packet loss\n",

           hostname, score->total, score->success,
           (score->total ? (score->total - score->success) * 100 / score->total
                         : 0));
    if (score->success && score->min != UINT32_MAX) {
        printf("round-trip min/avg/max/stddev = %.3f/%.3f/%.3f/%.3f ms\n",
               score->min, score->mean, score->max, get_stddev(score));
    }
}
*/