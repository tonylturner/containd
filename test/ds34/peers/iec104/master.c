/* SPDX-License-Identifier: Apache-2.0
 * Request exerciser only. All APCI, TCP and receiving use upstream lib60870.
 * No controlled-station handlers or expected response stages live here.
 */
#include "cs104_connection.h"
#include "hal_thread.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static pthread_mutex_t output = PTHREAD_MUTEX_INITIALIZER;
static CS104_Connection con;
static int case_id;
static bool testfr_seen;
static const uint8_t timestamp[] = {0, 0, 0, 0, 1, 1, 24};

static void raw(void* arg, uint8_t* msg, int size, bool sent)
{
    (void)arg;
    pthread_mutex_lock(&output);
    if (!sent && size == 6 && msg[2] == 0x83)
        testfr_seen = true;
    printf("%s ", sent ? "TX" : "RX");
    for (int i = 0; i < size; i++)
        printf("%02x", msg[i]);
    printf("\n");
    fflush(stdout);
    pthread_mutex_unlock(&output);
}

static void mark(const char* procedure, int type, int qualifier, const char* variant)
{
    pthread_mutex_lock(&output);
    printf("CASE %03d %s %d %d %s\n", ++case_id, procedure, type, qualifier, variant);
    fflush(stdout);
    pthread_mutex_unlock(&output);
}

static void request(const char* procedure, int type, int qualifier,
                    const char* variant, int cot, int ca, int ioa,
                    const uint8_t* payload, int size)
{
    mark(procedure, type, qualifier, variant);
    uint8_t bytes[64] = {(uint8_t)type, 1, (uint8_t)cot, 0,
                        (uint8_t)ca, (uint8_t)(ca >> 8),
                        (uint8_t)ioa, (uint8_t)(ioa >> 8), (uint8_t)(ioa >> 16)};
    memcpy(bytes + 9, payload, (size_t)size);
    CS101_ASDU asdu = CS101_ASDU_createFromBuffer(
        CS104_Connection_getAppLayerParameters(con), bytes, size + 9);
    if (!asdu || !CS104_Connection_sendASDU(con, asdu)) {
        fprintf(stderr, "request send failed: case %d\n", case_id);
        exit(1);
    }
    CS101_ASDU_destroy(asdu);
    /* Fixed observation window, including absent application responses.
     * This is not a protocol timeout and cannot prove optional-stage absence. */
    Thread_sleep(650);
}

static int command_payload(int type, bool select, uint8_t* payload)
{
    int base = type >= 58 ? type - 13 : type;
    int size = base <= 47 ? 1 : (base <= 49 ? 3 : (base == 50 ? 5 : 4));
    memset(payload, 0, 16);
    payload[0] = 1;
    if (base != 51)
        payload[base <= 47 ? 0 : size - 1] |= select ? 0x80 : 0;
    if (type >= 58) {
        memcpy(payload + size, timestamp, sizeof(timestamp));
        size += sizeof(timestamp);
    }
    return size;
}

int main(int argc, char** argv)
{
    bool typed_stations = argc == 2 && strcmp(argv[1], "c104") == 0;
    con = CS104_Connection_create("127.0.0.1", 2404);
    CS104_APCIParameters apci = CS104_Connection_getAPCIParameters(con);
    apci->t2 = 1;
    /* Below the C sample's 2 s periodic interval: otherwise its I traffic can
     * indefinitely suppress an inactivity-triggered TESTFR probe. */
    apci->t3 = 1;
    apci->w = 1;
    CS104_Connection_setRawMessageHandler(con, raw, NULL);
    mark("startdt", 0, 0, "session");
    if (!CS104_Connection_connect(con))
        return 1;
    CS104_Connection_sendStartDT(con);
    Thread_sleep(500);

    /* CP56Time2a: 2024-01-01 00:00:00; command timestamps intentionally fixed. */
    for (int type = 45; type <= 64; type++) {
        if (type == 52)
            type = 58;
        int base = type >= 58 ? type - 13 : type;
        if (base != 51) {
            uint8_t payload[16];
            int size = command_payload(type, false, payload);
            request("execute", type, 0, "without-select", 6,
                    typed_stations ? type : 1, 5000, payload, size);
            size = command_payload(type, true, payload);
            request("select", type, 0, "direct-point-5002", 6,
                    typed_stations ? type : 1, 5002, payload, size);
        }
        for (int bad = 0; bad < 2; bad++) {
            int phases = base == 51 ? 1 : 2;
            for (int phase = 0; phase < phases; phase++) {
                bool select = phases == 2 && phase == 0;
                uint8_t payload[16];
                int size = command_payload(type, select, payload);
                request(select ? "select" : "execute", type, 0,
                        bad ? "unknown-ioa" : "point-5000", 6, typed_stations ? type : 1,
                        bad ? 5001 : 5000, payload, size);
            }
        }
    }
    for (int qoi = 20; qoi <= 36; qoi++) {
        uint8_t q = (uint8_t)qoi;
        request("interrogation", 100, qoi, "ca-1", 6, 1, 0, &q, 1);
    }
    uint8_t q = 20;
    request("interrogation", 100, 20, "unknown-ca", 6, 2, 0, &q, 1);
    for (int freeze = 0; freeze <= 3; freeze++)
        for (int group = 1; group <= 5; group++) {
            q = (uint8_t)(group | (freeze << 6));
            request("counter", 101, q, "ca-1", 6, 1, 0, &q, 1);
        }
    const int reads[] = {100, 104, 110, 5000, 5001};
    for (unsigned i = 0; i < sizeof(reads) / sizeof(reads[0]); i++)
        request("read", 102, reads[i], "ca-1", 5, 1, reads[i], &q, 0);
    for (int bad = 0; bad < 2; bad++) {
        request("clock", 103, 0, bad ? "invalid-ioa" : "ioa-0",
                6, 1, bad, timestamp, sizeof(timestamp));
        for (int reset = 1; reset <= 2; reset++) {
            q = (uint8_t)reset;
            request("reset", 105, reset, bad ? "invalid-ioa" : "ioa-0",
                    6, 1, bad, &q, 1);
        }
        uint8_t test[9] = {0x38, 0x49};
        memcpy(test + 2, timestamp, sizeof(timestamp));
        request("test", 107, 0x4938, bad ? "invalid-ioa" : "ioa-0",
                6, 1, bad, test, sizeof(test));
    }
    /* Java's upstream sample deliberately does not answer Type49. Eight such
     * requests exercise its receive-window S acknowledgement without raw APCI. */
    for (int i = 0; i < 8; i++) {
        uint8_t payload[16];
        int size = command_payload(49, false, payload);
        request("s-ack-probe", 49, i, "unknown-ioa", 6,
                typed_stations ? 49 : 1, 5001, payload, size);
    }
    mark("idle", 0, 0, "autonomous-and-testfr");
    Thread_sleep(4500);
    pthread_mutex_lock(&output);
    bool tested = testfr_seen;
    pthread_mutex_unlock(&output);
    if (!tested) {
        fprintf(stderr, "TESTFR confirmation was not observed\n");
        CS104_Connection_destroy(con);
        return 1;
    }
    mark("stopdt", 0, 0, "session");
    CS104_Connection_sendStopDT(con);
    Thread_sleep(1500);
    CS104_Connection_destroy(con);
    return 0;
}
