#include <arpa/inet.h>
#include <curl/curl.h>

#include "SCIONSocket.h"

#define BUFSIZE 1024
#define PATHS 3

size_t dummy(void *buffer, size_t size, size_t nmemb, void *userp)
{
    return size * nmemb;
}

int main(int argc, char **argv)
{
    SCIONAddr addrs[1];
    SCIONAddr saddr;
    int isd, ad;
    char str[20];
    if (argc == 3) {
        isd = atoi(argv[1]);
        ad = atoi(argv[2]);
    } else {
        isd = 2;
        ad = 26;
    }
    saddr.isd_ad = ISD_AD(isd, ad);
    saddr.host.addrLen = 4;
    sprintf(str, "127.%d.%d.254", isd, ad);
    printf("connect to (%d, %d):%s\n", isd, ad, str);
    in_addr_t in = inet_addr(str);
    memcpy(saddr.host.addr, &in, 4);
    addrs[0] = saddr;
    SCIONSocket s(SCION_PROTO_SSP, addrs, 1, 0, 8080);
    int count = 0;
    char curldata[1024];
    char buf[BUFSIZE];
    memset(buf, 0, BUFSIZE);
    struct timeval start, end;
    gettimeofday(&start, NULL);
    CURL *curl;
    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    if (!curl) {
        printf("curl init failed\n");
        return 1;
    }
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, dummy);
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Accept: application/json");
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "charsets: utf-8");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    SCIONStats *stats;
    memset(&stats, 0, sizeof(stats));
    while (1) {
        sprintf(buf, "This is message %d\n", count);
        s.send((uint8_t *)buf, BUFSIZE);
        gettimeofday(&end, NULL);
        long us = end.tv_usec - start.tv_usec + (end.tv_sec - start.tv_sec) * 1000000;
        if (us > 1000000) {
            count++;
            start = end;
            stats = s.getStats();
            sprintf(curldata, "{\
                    \"packets\":{\
                    \"red\":[{\"time\":%d,\"value\":%.1f}],\
                    \"green\":[{\"time\":%d,\"value\":%.1f}],\
                    \"yellow\":[{\"time\":%d,\"value\":%.1f}]\
                    },\
                    \"delay\":{\
                    \"red\":[{\"time\":%d,\"value\":%.2f}],\
                    \"green\":[{\"time\":%d,\"value\":%.2f}],\
                    \"yellow\":[{\"time\":%d,\"value\":%.2f}]\
                    },\
                    \"loss\":{\
                    \"red\":[{\"time\":%d,\"value\":%.1f}],\
                    \"green\":[{\"time\":%d,\"value\":%.1f}],\
                    \"yellow\":[{\"time\":%d,\"value\":%.1f}]\
                    }\
                    }",
                    count, stats->sentPackets[0] / 1000.0,
                    count, stats->sentPackets[1] / 1000.0,
                    count, stats->sentPackets[2] / 1000.0,
                    count, (double)stats->rtts[0] / 1000,
                    count, (double)stats->rtts[1] / 1000,
                    count, (double)stats->rtts[2] / 1000,
                    count, stats->lossRates[0] * 100,
                    count, stats->lossRates[1] * 100,
                    count, stats->lossRates[2] * 100);
            curl_easy_setopt(curl, CURLOPT_URL, "http://192.33.93.167:8000/metrics");
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, curldata);
            curl_easy_perform(curl);
            destroyStats(stats);
        }
    }
    exit(0);
}
