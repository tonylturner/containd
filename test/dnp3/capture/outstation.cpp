/*
 * Copyright 2013-2020 Automatak, LLC
 *
 * Licensed to Green Energy Corp (www.greenenergycorp.com) and Automatak
 * LLC (www.automatak.com) under one or more contributor license agreements.
 * See the NOTICE file distributed with this work for additional information
 * regarding copyright ownership. Green Energy Corp and Automatak LLC license
 * this file to you under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License. You may obtain
 * a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


// Adapted from the opendnp3 outstation example. No containd linkage.
#include <opendnp3/ConsoleLogger.h>
#include <opendnp3/DNP3Manager.h>
#include <opendnp3/channel/PrintingChannelListener.h>
#include <opendnp3/logging/LogLevels.h>
#include <opendnp3/outstation/DefaultOutstationApplication.h>
#include <opendnp3/outstation/SimpleCommandHandler.h>
#include <opendnp3/outstation/UpdateBuilder.h>
#include <csignal>
#include <string>
#include <chrono>
#include <iostream>
#include <thread>

using namespace opendnp3;
static volatile std::sig_atomic_t stopped = 0;
static void stop(int) { stopped = 1; }

int main(int argc, char** argv)
{
    std::signal(SIGTERM, stop);
    DNP3Manager manager(1, ConsoleLogger::Create());
    auto channel = manager.AddTCPServer("server", levels::NORMAL | levels::ALL_COMMS,
        ServerAcceptMode::CloseExisting, IPEndpoint("0.0.0.0", 20000), PrintingChannelListener::Create());
    DatabaseConfig database;
    for (uint16_t i = 0; i < 700; ++i) {
        database.analog_input[i].svariation = StaticAnalogVariation::Group30Var1;
        database.analog_input[i].evariation = EventAnalogVariation::Group32Var1;
        database.analog_input[i].clazz = PointClass::Class1;
    }
    for (uint16_t i = 0; i < 16; ++i) database.binary_input[i].svariation = StaticBinaryVariation::Group1Var2;
    OutstationStackConfig config(database);
    config.link.LocalAddr = 10;
    config.link.RemoteAddr = 1;
    config.link.KeepAliveTimeout = TimeDuration::Seconds(1);
    config.outstation.params.allowUnsolicited = !(argc == 2 && std::string(argv[1]) == "link-only");
    config.outstation.params.maxTxFragSize = 1024; // several transport segments AND app fragments
    config.outstation.eventBufferConfig = EventBufferConfig::AllTypes(100);
    auto outstation = channel->AddOutstation("outstation", SuccessCommandHandler::Create(),
        DefaultOutstationApplication::Create(), config);
    outstation->Enable();
    std::cout << "READY" << std::endl;
    unsigned tick = 0;
    while (!stopped) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        if (++tick % 10 == 0) {
            UpdateBuilder updates;
            updates.Update(Analog(static_cast<double>(tick), Flags(1)), 300);
            outstation->Apply(updates.Build());
        }
    }
    return 0;
}
