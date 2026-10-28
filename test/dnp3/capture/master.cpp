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


// Adapted from the opendnp3 master example. All user tasks have checked results.
#include <opendnp3/ConsoleLogger.h>
#include <opendnp3/DNP3Manager.h>
#include <opendnp3/channel/PrintingChannelListener.h>
#include <opendnp3/logging/LogLevels.h>
#include <opendnp3/master/IMasterApplication.h>
#include <opendnp3/master/ICommandTaskResult.h>
#include <opendnp3/master/PrintingSOEHandler.h>
#include <atomic>
#include <chrono>
#include <future>
#include <iostream>
#include <stdexcept>
#include <thread>

using namespace opendnp3;
std::atomic<bool> failed{false};
class Application : public IMasterApplication {
public:
    UTCTimestamp Now() override {
        return UTCTimestamp(static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count()));
    }
    void OnTaskComplete(const TaskInfo& info) override {
        if (info.result != TaskCompletion::SUCCESS) failed = true;
    }
    void OnKeepAliveFailure() override { failed = true; }
};
class Completion : public ITaskCallback {
public:
    std::promise<TaskCompletion> promise;
    void OnStart() override {}
    void OnComplete(TaskCompletion result) override { promise.set_value(result); }
    void OnDestroyed() override {}
};
void wait(std::future<TaskCompletion>& future) {
    if (future.wait_for(std::chrono::seconds(10)) != std::future_status::ready || future.get() != TaskCompletion::SUCCESS)
        throw std::runtime_error("task timeout or unexpected task result");
}
int main(int argc, char** argv)
{
    if (argc != 3) return 2;
    const std::string scenario(argv[2]);
    DNP3Manager manager(1, ConsoleLogger::Create());
    auto channel = manager.AddTCPClient("master", levels::NORMAL | levels::ALL_COMMS, ChannelRetry::Default(),
        {IPEndpoint(argv[1], 20000)}, "0.0.0.0", PrintingChannelListener::Create());
    MasterStackConfig config;
    config.link.LocalAddr = 1;
    config.link.RemoteAddr = 10;
    config.link.KeepAliveTimeout = TimeDuration::Seconds(1);
    config.master.responseTimeout = TimeDuration::Seconds(3);
    // Isolate an otherwise idle link-only exchange; other scenarios retain startup tasks.
    if (scenario == "link-only") {
        config.master.startupIntegrityClassMask = ClassField::None();
        config.master.unsolClassMask = ClassField::None();
        config.master.disableUnsolOnStartup = false;
        config.master.ignoreRestartIIN = true;
    }
    auto master = channel->AddMaster("master", PrintingSOEHandler::Create(), std::make_shared<Application>(), config);
    master->Enable();
    std::this_thread::sleep_for(std::chrono::seconds(3));
    auto runScan = [&](const std::vector<Header>& headers) {
        auto cb = std::make_shared<Completion>(); auto future = cb->promise.get_future();
        master->Scan(headers, PrintingSOEHandler::Create(), TaskConfig::With(cb)); wait(future);
    };
    if (scenario == "startup-integrity" || scenario == "large-response") {
        auto cb = std::make_shared<Completion>(); auto future = cb->promise.get_future();
        master->ScanClasses(ClassField::AllClasses(), PrintingSOEHandler::Create(), TaskConfig::With(cb)); wait(future);
    } else if (scenario == "class-range") {
        runScan({Header::AllObjects(60, 2)});
        runScan({Header::Range8(1, 2, 3, 7), Header::Range16(30, 1, 295, 305)});
    } else if (scenario == "crob") {
        auto command = [&](bool select) {
            auto promise = std::make_shared<std::promise<TaskCompletion>>(); auto future = promise->get_future();
            auto callback = [promise](const ICommandTaskResult& result) {
                bool ok = result.summary == TaskCompletion::SUCCESS;
                result.ForeachItem([&](const CommandPointResult& point) { if (point.status != CommandStatus::SUCCESS) ok = false; });
                promise->set_value(ok ? TaskCompletion::SUCCESS : TaskCompletion::FAILURE_BAD_RESPONSE);
            };
            ControlRelayOutputBlock crob(OperationType::PULSE_ON, TripCloseCode::TRIP, false, 2, 250, 500);
            if (select) master->SelectAndOperate(crob, 300, callback);
            else master->DirectOperate(crob, 301, callback);
            wait(future);
        };
        command(true); command(false);
    } else if (scenario == "iin-error") {
        // Validly encoded request for an unknown object; the real outstation
        // supplies OBJECT_UNKNOWN IIN. It is an intentional application error.
        auto cb = std::make_shared<Completion>(); auto future = cb->promise.get_future();
        master->Scan({Header::AllObjects(99, 1)}, PrintingSOEHandler::Create(), TaskConfig(TaskId::Defined(99), cb));
        // A valid response completes the poll successfully even with error IIN.
        // The independent oracle, not task success, verifies OBJECT_UNKNOWN.
        wait(future);
    } else if (scenario != "link-only" && scenario != "unsolicited") {
        throw std::runtime_error("unknown scenario");
    }
    std::this_thread::sleep_for(std::chrono::seconds(3));
    if (failed) return 1;
    std::cout << "SCENARIO_COMPLETE " << scenario << std::endl;
    return 0;
}
