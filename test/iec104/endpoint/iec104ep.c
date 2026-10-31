/*
 * containd IEC 60870-5-104 truth-harness endpoint.
 * Copyright (C) 2026 The containd contributors
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This program links lib60870-C (MZ Automation, GPLv3-or-commercial), so it
 * is a GPLv3 combined work. It is built ONLY into the harness test image
 * (test/iec104/endpoint/Dockerfile) and is never linked into containd, which
 * stays Apache-2.0 with its own Go IEC104 parser. The
 * two talk only over the wire (TCP/2404). The corresponding source for the
 * pinned lib60870 release and this file ship in the image under
 * /usr/share/src, alongside the GPLv3 licence under /usr/share/licenses.
 *
 * Subcommands:
 *   rtu            substation RTU/server. Answers station GI for CA 1 and
 *                  CA 2, accepts a double command (type 46) at (CA 1, IOA
 *                  2001) as select-before-execute only, emits spontaneous
 *                  telemetry on a breaker change, and writes its point state
 *                  to the state file after every change so the harness can
 *                  prove a denied command did not actuate the plant.
 *   cc             control centre: connect, STARTDT, station GI, then idle
 *                  with periodic TESTFR. A long-lived monitored session.
 *   cmd SCENARIO   one-shot command client; see usage(). Exit 0 on a positive
 *                  confirmation, 1 on a negative/absent confirmation, 2 on a
 *                  usage or connection error, so the harness reads the plant's
 *                  answer rather than a timeout.
 *
 * The point map and command values are documented in test/iec104/README.md.
 * Verified against IEC 60870-5-104:2006+A1:2016 and -101:2003+A1:2005.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include "cs104_slave.h"
#include "cs104_connection.h"
#include "hal_thread.h"
#include "hal_time.h"

/* ---- shared point map ------------------------------------------------- */

#define CA_MAIN 1
#define CA_AUX 2
#define IOA_BREAKER_POS 1001   /* M_DP_NA_1 / M_DP_TB_1, monitor */
#define IOA_TRIP_STATUS 1002   /* M_SP_NA_1 / M_SP_TB_1, monitor */
#define IOA_STEP_POSITION 1301 /* M_ST_NA_1 / M_ST_TB_1, monitor */
#define IOA_FEEDER_CURRENT 1101 /* M_ME_NC_1, monitor */
#define IOA_BUSBAR_VOLTAGE 1102 /* M_ME_NC_1, monitor */
#define IOA_BREAKER_CMD 2001   /* C_DC_NA_1 on CA 1, policy-allowed breaker */
#define IOA_ISOLATOR_CMD 2002  /* C_DC_NA_1 on CA 1, a second device NOT in policy */
#define IOA_STALE_CMD 2003     /* C_DC_NA_1 on CA 1, target of the stale-retransmit probe */
#define IOA_AUX_FREQ 1201      /* M_ME_NC_1 on CA 2, monitor */
/* M_ME_NC_1 test measurements on CA 1 at the 16-bit and 24-bit IOA edges */
#define IOA_EDGE_16 65535
#define IOA_EDGE_17 65536
#define IOA_EDGE_24 16777215

/*
 * The RTU accepts the breaker double command (type 46, SBO) at three points so
 * the harness can test every policy dimension against a plant the RTU would
 * actually actuate: (CA 1, IOA 2001) is the policy-allowed breaker, (CA 1, IOA
 * 2002) is a second device the policy forbids (wrong-IOA case), (CA 1, IOA
 * 2003) is the target of the stale-retransmit probe, and (CA 2, IOA 2001) is
 * the aux station breaker (wrong-CA case). Every other (CA, IOA) is an
 * unknown address answered negatively with COT 47.
 */
static bool
isCommandPoint(int ca, int ioa)
{
    if (ca == CA_MAIN && (ioa == IOA_BREAKER_CMD || ioa == IOA_ISOLATOR_CMD || ioa == IOA_STALE_CMD))
        return true;
    if (ca == CA_AUX && ioa == IOA_BREAKER_CMD)
        return true;
    return false;
}

#define SELECT_TIMEOUT_MS 3000
#define RECONNECT_DELAY_MS 1000 /* control centre reconnect delay (<= 1 s) */

static volatile bool running = true;
static bool tripActive = false;
static int stepPosition = 12;

static void
sigint_handler(int signalId)
{
    (void)signalId;
    running = false;
}

/* ---- RTU -------------------------------------------------------------- */

static const char* stateFile = "/state/rtu.json";

static Semaphore rtuLock = NULL;
static int breakerPos = IEC60870_DOUBLE_POINT_ON; /* closed at startup */
static uint64_t writesApplied = 0;
static uint64_t giRequests = 0;
static uint64_t commandsReceived = 0;
static uint64_t connectionsOpened = 0;
static uint64_t connectionsClosed = 0;
static char lastCommand[64] = "none";

/* select-before-execute transaction state */
static bool selActive = false;
static int selValue = 0;
static int selCa = 0;
static int selIoa = 0;
static IMasterConnection selConn = NULL;
static uint64_t selAtMs = 0;
static char lastActuated[32] = "none";

/* GI progress, driven from the main loop as in the lib60870 example */
static int giState = 0;
static IMasterConnection giConn = NULL;
static int giProgress = 0;
static uint8_t giOa = 0;
static int giCa = CA_MAIN;

static void
writeState(void)
{
    char tmp[256];
    snprintf(tmp, sizeof(tmp), "%s.tmp", stateFile);
    FILE* f = fopen(tmp, "w");
    if (!f)
        return;
    fprintf(f,
        "{\"breaker_position\":%d,\"breaker_state\":\"%s\",\"writes_applied\":%llu,"
        "\"gi_requests\":%llu,\"commands_received\":%llu,"
        "\"connections_opened\":%llu,\"connections_closed\":%llu,"
        "\"last_actuated\":\"%s\",\"last_command\":\"%s\"}\n",
        breakerPos,
        breakerPos == IEC60870_DOUBLE_POINT_ON ? "closed" : "open",
        (unsigned long long)writesApplied,
        (unsigned long long)giRequests,
        (unsigned long long)commandsReceived,
        (unsigned long long)connectionsOpened,
        (unsigned long long)connectionsClosed,
        lastActuated,
        lastCommand);
    fclose(f);
    rename(tmp, stateFile);
}

static void
addMeasured(CS101_ASDU asdu, int ioa, float value)
{
    InformationObject io = (InformationObject)
        MeasuredValueShort_create(NULL, ioa, value, IEC60870_QUALITY_GOOD);
    CS101_ASDU_addInformationObject(asdu, io);
    InformationObject_destroy(io);
}

static void
sendBreakerSpontaneous(CS104_Slave slave)
{
    CS101_AppLayerParameters alp = CS104_Slave_getAppLayerParameters(slave);
    struct sCP56Time2a ts;
    CP56Time2a_createFromMsTimestamp(&ts, Hal_getTimeInMs());
    CS101_ASDU asdu = CS101_ASDU_create(alp, false, CS101_COT_SPONTANEOUS, 0, CA_MAIN, false, false);
    InformationObject io = (InformationObject)
        DoublePointWithCP56Time2a_create(NULL, IOA_BREAKER_POS, (DoublePointValue)breakerPos,
            IEC60870_QUALITY_GOOD, &ts);
    CS101_ASDU_addInformationObject(asdu, io);
    InformationObject_destroy(io);
    CS104_Slave_enqueueASDU(slave, asdu);
    CS101_ASDU_destroy(asdu);
}

static void
sendTripSpontaneous(CS104_Slave slave)
{
    CS101_AppLayerParameters alp = CS104_Slave_getAppLayerParameters(slave);
    struct sCP56Time2a ts;
    CP56Time2a_createFromMsTimestamp(&ts, Hal_getTimeInMs());
    CS101_ASDU asdu = CS101_ASDU_create(alp, false, CS101_COT_SPONTANEOUS, 0, CA_MAIN, false, false);
    InformationObject io = (InformationObject)
        SinglePointWithCP56Time2a_create(NULL, IOA_TRIP_STATUS, tripActive, IEC60870_QUALITY_GOOD, &ts);
    CS101_ASDU_addInformationObject(asdu, io);
    InformationObject_destroy(io);
    CS104_Slave_enqueueASDU(slave, asdu);
    CS101_ASDU_destroy(asdu);
}

static void
sendStepPositionSpontaneous(CS104_Slave slave)
{
    CS101_AppLayerParameters alp = CS104_Slave_getAppLayerParameters(slave);
    struct sCP56Time2a ts;
    CP56Time2a_createFromMsTimestamp(&ts, Hal_getTimeInMs());
    CS101_ASDU asdu = CS101_ASDU_create(alp, false, CS101_COT_SPONTANEOUS, 0, CA_MAIN, false, false);
    InformationObject io = (InformationObject)
        StepPositionWithCP56Time2a_create(NULL, IOA_STEP_POSITION, stepPosition, false,
            IEC60870_QUALITY_GOOD, &ts);
    CS101_ASDU_addInformationObject(asdu, io);
    InformationObject_destroy(io);
    CS104_Slave_enqueueASDU(slave, asdu);
    CS101_ASDU_destroy(asdu);
}

static void
handleGeneralInterrogation(CS104_Slave slave)
{
    Semaphore_wait(rtuLock);
    if (giState == 1 && giConn != NULL)
    {
        CS101_AppLayerParameters alp = CS104_Slave_getAppLayerParameters(slave);
        /* CA 1 answers with type 3 breaker position, type 1 trip status,
         * type 5 step position, then type 13 measurements (SQ=0, five
         * objects incl. IOA edges).
         * CA 2 answers with one type 13 ASDU. */
        if (giProgress == 0 && giCa == CA_MAIN)
        {
            CS101_ASDU asdu = CS101_ASDU_create(alp, false, CS101_COT_INTERROGATED_BY_STATION,
                giOa, giCa, false, false);
            InformationObject io = (InformationObject)
                DoublePointInformation_create(NULL, IOA_BREAKER_POS, (DoublePointValue)breakerPos,
                    IEC60870_QUALITY_GOOD);
            CS101_ASDU_addInformationObject(asdu, io);
            InformationObject_destroy(io);
            if (IMasterConnection_sendASDUEx(giConn, asdu, true))
                giProgress++;
            CS101_ASDU_destroy(asdu);
        }
        else if (giProgress == 0)
        {
            giProgress++;
        }
        else if (giProgress == 1)
        {
            if (giCa == CA_MAIN)
            {
                CS101_ASDU asdu = CS101_ASDU_create(alp, false, CS101_COT_INTERROGATED_BY_STATION,
                    giOa, giCa, false, false);
                InformationObject io = (InformationObject)
                    SinglePointInformation_create(NULL, IOA_TRIP_STATUS, tripActive, IEC60870_QUALITY_GOOD);
                CS101_ASDU_addInformationObject(asdu, io);
                InformationObject_destroy(io);
                if (IMasterConnection_sendASDUEx(giConn, asdu, true))
                    giProgress++;
                CS101_ASDU_destroy(asdu);
            }
            else
            {
                giProgress++;
            }
        }
        else if (giProgress == 2)
        {
            if (giCa == CA_MAIN)
            {
                CS101_ASDU asdu = CS101_ASDU_create(alp, false, CS101_COT_INTERROGATED_BY_STATION,
                    giOa, giCa, false, false);
                InformationObject io = (InformationObject)
                    StepPositionInformation_create(NULL, IOA_STEP_POSITION, stepPosition, false,
                        IEC60870_QUALITY_GOOD);
                CS101_ASDU_addInformationObject(asdu, io);
                InformationObject_destroy(io);
                if (IMasterConnection_sendASDUEx(giConn, asdu, true))
                    giProgress++;
                CS101_ASDU_destroy(asdu);
            }
            else
            {
                giProgress++;
            }
        }
        else if (giProgress == 3)
        {
            CS101_ASDU asdu = CS101_ASDU_create(alp, false, CS101_COT_INTERROGATED_BY_STATION,
                giOa, giCa, false, false);
            if (giCa == CA_MAIN)
            {
                addMeasured(asdu, IOA_FEEDER_CURRENT, breakerPos == IEC60870_DOUBLE_POINT_ON ? 182.5f : 0.0f);
                addMeasured(asdu, IOA_BUSBAR_VOLTAGE, 20.4f);
                addMeasured(asdu, IOA_EDGE_16, 65.535f);
                addMeasured(asdu, IOA_EDGE_17, 65.536f);
                addMeasured(asdu, IOA_EDGE_24, 167.77215f);
            }
            else
            {
                addMeasured(asdu, IOA_AUX_FREQ, 50.02f);
            }
            if (IMasterConnection_sendASDUEx(giConn, asdu, true))
                giProgress++;
            CS101_ASDU_destroy(asdu);
        }
        else if (giProgress == 4)
        {
            CS101_ASDU asdu = CS101_ASDU_create(alp, false, CS101_COT_ACTIVATION_TERMINATION,
                giOa, giCa, false, false);
            InformationObject io = (InformationObject) InterrogationCommand_create(NULL, 0, 20);
            CS101_ASDU_addInformationObject(asdu, io);
            InformationObject_destroy(io);
            IMasterConnection_sendASDU(giConn, asdu);
            CS101_ASDU_destroy(asdu);
            giState = 0;
            giConn = NULL;
            giProgress = 0;
        }
    }
    Semaphore_post(rtuLock);
}

static bool
interrogationHandler(void* parameter, IMasterConnection connection, CS101_ASDU asdu, uint8_t qoi)
{
    (void)parameter;
    int ca = CS101_ASDU_getCA(asdu);
    Semaphore_wait(rtuLock);
    giRequests++;
    writeState();
    Semaphore_post(rtuLock);
    if ((ca == CA_MAIN || ca == CA_AUX) && qoi == IEC60870_QOI_STATION)
    {
        Semaphore_wait(rtuLock);
        giState = 1;
        giConn = connection;
        giProgress = 0;
        giOa = (uint8_t)CS101_ASDU_getOA(asdu);
        giCa = ca;
        IMasterConnection_sendACT_CON(connection, asdu, false);
        Semaphore_post(rtuLock);
    }
    else
    {
        CS101_ASDU_setCOT(asdu, CS101_COT_UNKNOWN_CA);
        CS101_ASDU_setNegative(asdu, true);
        IMasterConnection_sendASDU(connection, asdu);
    }
    return true;
}

/* Breaker double command: select-before-execute only, at (CA 1, IOA 2001). */
static void
handleDoubleCommand(IMasterConnection connection, CS101_ASDU asdu)
{
    InformationObject io = CS101_ASDU_getElement(asdu, 0);
    if (!io)
        return;
    int ioa = InformationObject_getObjectAddress(io);
    DoubleCommand dc = (DoubleCommand)io;
    int value = DoubleCommand_getState(dc);
    bool select = DoubleCommand_isSelect(dc);
    int ca = CS101_ASDU_getCA(asdu);

    if (!isCommandPoint(ca, ioa))
    {
        /* unassigned command address */
        CS101_ASDU_setCOT(asdu, CS101_COT_UNKNOWN_IOA);
        CS101_ASDU_setNegative(asdu, true);
        IMasterConnection_sendASDU(connection, asdu);
        InformationObject_destroy(io);
        return;
    }
    if (value != IEC60870_DOUBLE_POINT_OFF && value != IEC60870_DOUBLE_POINT_ON)
    {
        CS101_ASDU_setCOT(asdu, CS101_COT_ACTIVATION_CON);
        CS101_ASDU_setNegative(asdu, true);
        IMasterConnection_sendASDU(connection, asdu);
        InformationObject_destroy(io);
        return;
    }

    Semaphore_wait(rtuLock);
    bool positive;
    if (select)
    {
        selActive = true;
        selValue = value;
        selCa = ca;
        selIoa = ioa;
        selConn = connection;
        selAtMs = Hal_getTimeInMs();
        positive = true;
        snprintf(lastCommand, sizeof(lastCommand), "select ca=%d ioa=%d dcs=%d", ca, ioa, value);
    }
    else
    {
        uint64_t now = Hal_getTimeInMs();
        bool ok = selActive && selConn == connection && selValue == value &&
                  selCa == ca && selIoa == ioa && (now - selAtMs) <= SELECT_TIMEOUT_MS;
        selActive = false;
        selConn = NULL;
        if (ok)
        {
            /* Only the policy-allowed breaker drives the published breaker
             * state; every accepted execute increments writes_applied so the
             * harness can see that a forbidden command actuated the plant. */
            if (ca == CA_MAIN && ioa == IOA_BREAKER_CMD)
                breakerPos = value;
            writesApplied++;
            positive = true;
            snprintf(lastActuated, sizeof(lastActuated), "%d:%d", ca, ioa);
            snprintf(lastCommand, sizeof(lastCommand), "execute ca=%d ioa=%d dcs=%d", ca, ioa, value);
        }
        else
        {
            positive = false;
            snprintf(lastCommand, sizeof(lastCommand), "execute-rejected ca=%d ioa=%d dcs=%d", ca, ioa, value);
        }
    }
    writeState();
    Semaphore_post(rtuLock);

    CS101_ASDU_setCOT(asdu, CS101_COT_ACTIVATION_CON);
    CS101_ASDU_setNegative(asdu, !positive);
    IMasterConnection_sendASDU(connection, asdu);
    /* execute positive: send ACT_TERM */
    if (positive && !select)
        IMasterConnection_sendACT_TERM(connection, asdu);
    InformationObject_destroy(io);
}

static bool
asduHandler(void* parameter, IMasterConnection connection, CS101_ASDU asdu)
{
    (void)parameter;
    /* Every ASDU that reaches this handler (all but GI) counts as received,
     * whatever the RTU then answers. */
    Semaphore_wait(rtuLock);
    commandsReceived++;
    writeState();
    Semaphore_post(rtuLock);
    if (CS101_ASDU_getTypeID(asdu) == C_DC_NA_1 &&
        CS101_ASDU_getCOT(asdu) == CS101_COT_ACTIVATION)
    {
        handleDoubleCommand(connection, asdu);
        return true;
    }
    /* Record receipt of every other ASDU so the harness can prove a denied
     * command of another type never reached the RTU; lib60870 then answers it
     * negatively (unknown type ID). */
    int ioa = -1;
    InformationObject io = CS101_ASDU_getElement(asdu, 0);
    if (io)
    {
        ioa = InformationObject_getObjectAddress(io);
        InformationObject_destroy(io);
    }
    Semaphore_wait(rtuLock);
    snprintf(lastCommand, sizeof(lastCommand), "rx type=%d ca=%d ioa=%d cot=%d",
        CS101_ASDU_getTypeID(asdu), CS101_ASDU_getCA(asdu), ioa, CS101_ASDU_getCOT(asdu));
    writeState();
    Semaphore_post(rtuLock);
    return false;
}

static void
connectionEventHandler(void* parameter, IMasterConnection con, CS104_PeerConnectionEvent event)
{
    (void)parameter;
    if (event == CS104_CON_EVENT_CONNECTION_OPENED || event == CS104_CON_EVENT_CONNECTION_CLOSED)
    {
        Semaphore_wait(rtuLock);
        if (event == CS104_CON_EVENT_CONNECTION_OPENED)
            connectionsOpened++;
        else
            connectionsClosed++;
        writeState();
        Semaphore_post(rtuLock);
    }
    if (event == CS104_CON_EVENT_CONNECTION_CLOSED || event == CS104_CON_EVENT_DEACTIVATED)
    {
        /* Only the closing connection's interrogation and selection end:
         * another client's close must not cancel them. */
        Semaphore_wait(rtuLock);
        if (giConn == con)
        {
            giState = 0;
            giConn = NULL;
            giProgress = 0;
        }
        if (selConn == con)
        {
            selActive = false;
            selConn = NULL;
        }
        Semaphore_post(rtuLock);
    }
}

static int
runRtu(void)
{
    const char* env = getenv("STATE_FILE");
    if (env && *env)
        stateFile = env;
    /* PERIODIC_MS: period of the spontaneous (COT 3) feeder-current update;
     * every fifth period also sends a cyclic (COT 1) busbar voltage. 0
     * disables both, so an idle client reaches t3 and exchanges TESTFR. */
    int periodicMs = 2000;
    env = getenv("PERIODIC_MS");
    if (env && *env)
        periodicMs = atoi(env);

    int port = 2404;
    env = getenv("IEC104_PORT");
    if (env && *env)
    {
        char* end = NULL;
        long parsed = strtol(env, &end, 10);
        if (*end != '\0' || parsed < 1 || parsed > 65535)
        {
            fprintf(stderr, "invalid IEC104_PORT: %s\n", env);
            return 2;
        }
        port = (int) parsed;
    }

    rtuLock = Semaphore_create(1);
    CS104_Slave slave = CS104_Slave_create(50, 50);
    CS104_Slave_setLocalAddress(slave, "0.0.0.0");
    CS104_Slave_setLocalPort(slave, port);
    /* Every connection is its own redundancy group: each active session gets
     * every event, so a long-lived control centre keeps its telemetry while
     * one-shot command clients come and go. */
    CS104_Slave_setServerMode(slave, CS104_MODE_CONNECTION_IS_REDUNDANCY_GROUP);
    CS104_Slave_setInterrogationHandler(slave, interrogationHandler, NULL);
    CS104_Slave_setASDUHandler(slave, asduHandler, NULL);
    CS104_Slave_setConnectionEventHandler(slave, connectionEventHandler, NULL);

    writeState();
    CS104_Slave_start(slave);
    if (!CS104_Slave_isRunning(slave))
    {
        fprintf(stderr, "RTU failed to start\n");
        CS104_Slave_destroy(slave);
        return 1;
    }
    printf("RTU listening on 0.0.0.0:%d (state file %s)\n", port, stateFile);
    fflush(stdout);

    int lastBreaker = breakerPos;
    uint64_t lastPeriodic = 0;
    uint64_t tick = 0;
    while (running)
    {
        handleGeneralInterrogation(slave);
        Semaphore_wait(rtuLock);
        int nowBreaker = breakerPos;
        Semaphore_post(rtuLock);
        if (nowBreaker != lastBreaker)
        {
            lastBreaker = nowBreaker;
            sendBreakerSpontaneous(slave);
        }
        uint64_t now = Hal_getMonotonicTimeInMs();
        if (periodicMs > 0 && now >= lastPeriodic + (uint64_t)periodicMs)
        {
            lastPeriodic = now;
            tick++;
            CS101_AppLayerParameters alp = CS104_Slave_getAppLayerParameters(slave);
            sendTripSpontaneous(slave);
            sendStepPositionSpontaneous(slave);
            /* feeder current drifts by +/-0.1 A so each update is a change */
            float current = nowBreaker == IEC60870_DOUBLE_POINT_ON ? 182.5f + (float)(tick % 3) * 0.1f : 0.0f;
            CS101_ASDU asdu = CS101_ASDU_create(alp, false, CS101_COT_SPONTANEOUS, 0, CA_MAIN, false, false);
            addMeasured(asdu, IOA_FEEDER_CURRENT, current);
            CS104_Slave_enqueueASDU(slave, asdu);
            CS101_ASDU_destroy(asdu);
            if (tick % 5 == 0)
            {
                asdu = CS101_ASDU_create(alp, false, CS101_COT_PERIODIC, 0, CA_MAIN, false, false);
                addMeasured(asdu, IOA_BUSBAR_VOLTAGE, 20.4f);
                CS104_Slave_enqueueASDU(slave, asdu);
                CS101_ASDU_destroy(asdu);
            }
        }
        Thread_sleep(20);
    }
    CS104_Slave_stop(slave);
    CS104_Slave_destroy(slave);
    Semaphore_destroy(rtuLock);
    return 0;
}

/* ---- client (cc and cmd) --------------------------------------------- */

static volatile bool lastConfirmPositive = false;
static volatile bool confirmSeen = false;
/* The command type whose confirmation cmd waits for. */
static volatile int awaitType = C_DC_NA_1;

static bool
clientAsduHandler(void* parameter, int address, CS101_ASDU asdu)
{
    (void)parameter;
    (void)address;
    CS101_CauseOfTransmission cot = CS101_ASDU_getCOT(asdu);
    int type = CS101_ASDU_getTypeID(asdu);
    int ioa = -1;
    if (CS101_ASDU_getNumberOfElements(asdu) > 0)
    {
        InformationObject io = CS101_ASDU_getElement(asdu, 0);
        if (io)
            ioa = InformationObject_getObjectAddress(io);
    }
    printf("t=%llu RCVD type=%d cot=%d negative=%d elements=%d ioa=%d\n",
        (unsigned long long)Hal_getTimeInMs(),
        type, cot, CS101_ASDU_isNegative(asdu), CS101_ASDU_getNumberOfElements(asdu), ioa);
    fflush(stdout);
    if (type == awaitType &&
        (cot == CS101_COT_ACTIVATION_CON || cot == CS101_COT_ACTIVATION_TERMINATION))
    {
        confirmSeen = true;
        lastConfirmPositive = !CS101_ASDU_isNegative(asdu);
    }
    else if (type == awaitType && cot >= CS101_COT_UNKNOWN_TYPE_ID && cot <= CS101_COT_UNKNOWN_IOA)
    {
        /* COT 44-47: the RTU rejected the command's type, cause, CA or IOA. */
        confirmSeen = true;
        lastConfirmPositive = false;
    }
    return true;
}

/* Set by the connection handler when the session closes or fails, so the
 * control centre loop knows to reconnect. */
static volatile bool clientClosed = false;

static void
clientConnectionHandler(void* parameter, CS104_Connection connection, CS104_ConnectionEvent event)
{
    (void)parameter;
    (void)connection;
    const char* name = "unknown";
    switch (event)
    {
    case CS104_CONNECTION_OPENED: name = "opened"; break;
    case CS104_CONNECTION_CLOSED: name = "closed"; break;
    case CS104_CONNECTION_STARTDT_CON_RECEIVED: name = "startdt_con"; break;
    case CS104_CONNECTION_STOPDT_CON_RECEIVED: name = "stopdt_con"; break;
    case CS104_CONNECTION_FAILED: name = "failed"; break;
    }
    if (event == CS104_CONNECTION_CLOSED || event == CS104_CONNECTION_FAILED)
        clientClosed = true;
    printf("t=%llu CONN %s\n", (unsigned long long)Hal_getTimeInMs(), name);
    fflush(stdout);
}

static CS104_Connection
openConnection(const char* host, int port)
{
    CS104_Connection con = CS104_Connection_create(host, port);
    /* IEC104_T3: client idle timer in seconds (default lib60870 20 s). */
    const char* t3 = getenv("IEC104_T3");
    if (t3 && *t3)
    {
        CS104_APCIParameters apci = CS104_Connection_getAPCIParameters(con);
        apci->t3 = atoi(t3);
    }
    CS104_Connection_setASDUReceivedHandler(con, clientAsduHandler, NULL);
    CS104_Connection_setConnectionHandler(con, clientConnectionHandler, NULL);
    CS104_Connection_setConnectTimeout(con, 2000);
    if (!CS104_Connection_connect(con))
    {
        fprintf(stderr, "connect to %s:%d failed\n", host, port);
        CS104_Connection_destroy(con);
        return NULL;
    }
    CS104_Connection_sendStartDT(con);
    Thread_sleep(500);
    return con;
}

static int
runCc(const char* host, int port)
{
    /* A real control centre: after the session closes or is
     * reset, wait at most 1 s, reconnect, STARTDT and re-run station GI. Each
     * session logs "t=<ms> CC connected"; closes log "t=<ms> CONN closed". */
    signal(SIGINT, sigint_handler);
    while (running)
    {
        clientClosed = false;
        CS104_Connection con = openConnection(host, port);
        if (!con)
        {
            Thread_sleep(RECONNECT_DELAY_MS);
            continue;
        }
        printf("t=%llu CC connected to %s:%d\n", (unsigned long long)Hal_getTimeInMs(), host, port);
        fflush(stdout);
        CS104_Connection_sendInterrogationCommand(con, CS101_COT_ACTIVATION, CA_MAIN, IEC60870_QOI_STATION);
        uint64_t lastGi = Hal_getMonotonicTimeInMs();
        while (running && !clientClosed)
        {
            Thread_sleep(100);
            uint64_t now = Hal_getMonotonicTimeInMs();
            if (now >= lastGi + 30000)
            {
                lastGi = now;
                CS104_Connection_sendInterrogationCommand(con, CS101_COT_ACTIVATION, CA_MAIN, IEC60870_QOI_STATION);
            }
        }
        CS104_Connection_destroy(con);
        if (running)
            Thread_sleep(RECONNECT_DELAY_MS);
    }
    return 0;
}

static int
waitConfirm(int timeoutMs)
{
    int waited = 0;
    while (!confirmSeen && waited < timeoutMs)
    {
        Thread_sleep(50);
        waited += 50;
    }
    if (!confirmSeen)
    {
        fprintf(stderr, "no confirmation within %d ms\n", timeoutMs);
        return 1;
    }
    return lastConfirmPositive ? 0 : 1;
}

static int
sendDoubleCommand(CS104_Connection con, int ca, int ioa, int value, bool select, int qualifier)
{
    confirmSeen = false;
    InformationObject io = (InformationObject) DoubleCommand_create(NULL, ioa, value, select, qualifier);
    bool sent = CS104_Connection_sendProcessCommandEx(con, CS101_COT_ACTIVATION, ca, io);
    InformationObject_destroy(io);
    if (!sent)
    {
        fprintf(stderr, "failed to queue command\n");
        return 2;
    }
    return waitConfirm(4000);
}

static int
runCmd(const char* host, int port, int argc, char** argv)
{
    if (argc < 1)
    {
        fprintf(stderr, "cmd needs a scenario\n");
        return 2;
    }
    const char* scenario = argv[0];
    CS104_Connection con = openConnection(host, port);
    if (!con)
        return 2;

    int rc = 2;
    if (strcmp(scenario, "gi") == 0)
    {
        int ca = (argc > 1) ? atoi(argv[1]) : CA_MAIN;
        confirmSeen = false;
        CS104_Connection_sendInterrogationCommand(con, CS101_COT_ACTIVATION, ca, IEC60870_QOI_STATION);
        Thread_sleep(2000);
        rc = 0;
    }
    else if (strcmp(scenario, "sbo") == 0)
    {
        /* sbo CA IOA VALUE : select then execute the same value */
        if (argc < 4) { rc = 2; }
        else
        {
            int ca = atoi(argv[1]), ioa = atoi(argv[2]), value = atoi(argv[3]);
            int sel = sendDoubleCommand(con, ca, ioa, value, true, 0);
            if (sel != 0) { rc = sel; }
            else { rc = sendDoubleCommand(con, ca, ioa, value, false, 0); }
        }
    }
    else if (strcmp(scenario, "sboq") == 0)
    {
        /* sboq CA IOA VALUE QU: select then execute with the same QU. */
        if (argc < 5) { rc = 2; }
        else
        {
            int ca = atoi(argv[1]), ioa = atoi(argv[2]), value = atoi(argv[3]), qualifier = atoi(argv[4]);
            if (qualifier < 0 || qualifier > 31) { rc = 2; }
            else
            {
                int sel = sendDoubleCommand(con, ca, ioa, value, true, qualifier);
                if (sel != 0) { rc = sel; }
                else { rc = sendDoubleCommand(con, ca, ioa, value, false, qualifier); }
            }
        }
    }
    else if (strcmp(scenario, "select") == 0)
    {
        if (argc < 4) { rc = 2; }
        else { rc = sendDoubleCommand(con, atoi(argv[1]), atoi(argv[2]), atoi(argv[3]), true, 0); }
    }
    else if (strcmp(scenario, "execute") == 0)
    {
        if (argc < 4) { rc = 2; }
        else { rc = sendDoubleCommand(con, atoi(argv[1]), atoi(argv[2]), atoi(argv[3]), false, 0); }
    }
    else if (strcmp(scenario, "single") == 0)
    {
        /* single CA IOA VALUE : a type 45 single command (direct execute).
         * The RTU has no type 45 point; it records receipt and lib60870
         * answers negatively, so exit 1 is expected when it arrives. */
        if (argc < 4) { rc = 2; }
        else
        {
            confirmSeen = false;
            InformationObject io = (InformationObject)
                SingleCommand_create(NULL, atoi(argv[2]), atoi(argv[3]) != 0, false, 0);
            bool sent = CS104_Connection_sendProcessCommandEx(con, CS101_COT_ACTIVATION, atoi(argv[1]), io);
            InformationObject_destroy(io);
            awaitType = C_SC_NA_1;
            rc = sent ? waitConfirm(4000) : 2;
        }
    }
    else if (strcmp(scenario, "stopstart") == 0)
    {
        /* STOPDT act/con, then STARTDT act/con again on the same session */
        CS104_Connection_sendStopDT(con);
        Thread_sleep(1000);
        CS104_Connection_sendStartDT(con);
        Thread_sleep(1000);
        rc = 0;
    }
    else if (strcmp(scenario, "direct") == 0)
    {
        /* direct CA IOA VALUE : execute with no prior select (expected negative) */
        if (argc < 4) { rc = 2; }
        else { rc = sendDoubleCommand(con, atoi(argv[1]), atoi(argv[2]), atoi(argv[3]), false, 0); }
    }
    else
    {
        fprintf(stderr, "unknown scenario %s\n", scenario);
        rc = 2;
    }
    CS104_Connection_destroy(con);
    return rc;
}

/* ---- entry ------------------------------------------------------------ */

static int
usage(void)
{
    fprintf(stderr,
        "usage: iec104ep rtu\n"
        "       iec104ep cc  HOST [PORT]\n"
        "       iec104ep cmd HOST PORT SCENARIO [ARGS]\n"
        "scenarios: gi [CA] | sbo CA IOA VALUE | sboq CA IOA VALUE QU | select CA IOA VALUE |\n"
        "           execute CA IOA VALUE | direct CA IOA VALUE |\n"
        "           single CA IOA VALUE | stopstart\n"
        "env: RTU STATE_FILE, IEC104_PORT (2404), PERIODIC_MS (0 disables); client IEC104_T3 seconds\n"
        "double-command VALUE: 1=open 2=close\n");
    return 2;
}

int
main(int argc, char** argv)
{
    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);
    if (argc < 2)
        return usage();
    if (strcmp(argv[1], "rtu") == 0)
        return runRtu();
    if (strcmp(argv[1], "cc") == 0)
    {
        if (argc < 3)
            return usage();
        int port = (argc > 3) ? atoi(argv[3]) : 2404;
        return runCc(argv[2], port);
    }
    if (strcmp(argv[1], "cmd") == 0)
    {
        if (argc < 5)
            return usage();
        return runCmd(argv[2], atoi(argv[3]), argc - 4, argv + 4);
    }
    return usage();
}
