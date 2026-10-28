// SPDX-License-Identifier: Apache-2.0
// Endpoint driver: all requests use EIPScanner; every reply is from OpENer.
#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <string>
#include "SessionInfo.h"
#include "ConnectionManager.h"
#include "cip/MessageRouterRequest.h"
#include "cip/connectionManager/ForwardOpenRequest.h"
#include "cip/connectionManager/ForwardOpenResponse.h"
#include "cip/connectionManager/ForwardCloseRequest.h"
#include "cip/connectionManager/NetworkConnectionParams.h"
#include "eip/CommonPacket.h"
#include "utils/Buffer.h"
#include "utils/Logger.h"

using namespace eipScanner;
using namespace eipScanner::cip;
using namespace eipScanner::cip::connectionManager;
using namespace eipScanner::eip;
using eipScanner::utils::Buffer;

static void require(bool ok, const std::string& message) {
    if (!ok) throw std::runtime_error(message);
}
static void status(const MessageRouterResponse& response, unsigned expected) {
    auto value = static_cast<unsigned>(response.getGeneralStatusCode());
    std::cout << "status=0x" << std::hex << value << " additional=";
    for (auto word : response.getAdditionalStatus()) std::cout << "0x" << word << ",";
    std::cout << std::dec << std::endl;
    require(value == expected, "unexpected adapter status");
}
static ConnectionParameters parameters() {
    ConnectionParameters p;
    p.originatorVendorId = 342;
    p.originatorSerialNumber = 0x12345;
    p.connectionSerialNumber = 123;
    p.priorityTimeTick = 10;
    p.timeoutTicks = 100;
    p.o2tRPI = p.t2oRPI = 100000;
    p.o2tNetworkConnectionParams = p.t2oNetworkConnectionParams =
        NetworkConnectionParams::P2P | NetworkConnectionParams::SCHEDULED_PRIORITY | 32;
    p.o2tRealTimeFormat = true;
    p.transportTypeTrigger = NetworkConnectionParams::CLASS1;
    p.connectionPath = {0x20, 4, 0x24, 151, 0x2c, 150, 0x2c, 100};
    return p;
}
static void explicitMessages(const SessionInfo::SPtr& si) {
    MessageRouter router(true);
    status(router.sendRequest(si, 0x0e, EPath(1, 1, 1)), 0);
    status(router.sendRequest(si, 0x10, EPath(4, 154, 3), std::vector<uint8_t>(32, 0x5a)), 0);
    status(router.sendRequest(si, 0x0e, EPath(4, 154, 3)), 0);
    status(router.sendRequest(si, 0x0e, EPath(1, 1, 99)), 0x14);
    // Correctly framed but wrong assembly size, handled by the real adapter.
    status(router.sendRequest(si, 0x10, EPath(4, 154, 3), {1}), 0x13);
    auto p = parameters();
    p.connectionPath[5] = 149; // nonexistent consuming connection point
    p.connectionPathSize = p.connectionPath.size() / 2;
    p.o2tNetworkConnectionParams += 6;
    p.t2oNetworkConnectionParams += 2;
    auto response = router.sendRequest(si, 0x54, EPath(6, 1), ForwardOpenRequest(p).pack());
    status(response, 1);
    require(!response.getAdditionalStatus().empty(), "missing ForwardOpen additional status");
}
static void implicitMessages(const SessionInfo::SPtr& si) {
    ConnectionManager manager;
    auto io = manager.forwardOpen(si, parameters());
    auto connection = io.lock();
    require(bool(connection), "class 1 ForwardOpen failed");
    unsigned received = 0;
    connection->setDataToSend(std::vector<uint8_t>(32, 0x3c));
    connection->setReceiveDataListener([&received](auto, auto, auto data) {
        require(data.size() == 32, "wrong I/O assembly size");
        ++received;
    });
    for (int i = 0; i < 30 && received < 3; ++i)
        manager.handleConnections(std::chrono::milliseconds(100));
    require(received >= 3, "did not receive three native I/O datagrams");
    manager.forwardClose(si, io);
    require(!manager.hasOpenConnections(), "I/O connection still open");
    std::cout << "native class1 received=" << received << std::endl;
}
static void connectedMessages(const SessionInfo::SPtr& si) {
    MessageRouter router(true);
    auto p = parameters();
    p.connectionSerialNumber = 124;
    p.o2tRealTimeFormat = false;
    p.transportTypeTrigger = 0xa3; // class 3, application trigger, server
    p.o2tNetworkConnectionParams = p.t2oNetworkConnectionParams = 0x43f4;
    p.t2oNetworkConnectionId = 0x12345678;
    p.connectionPath = {0x20, 2, 0x24, 1};
    p.connectionPathSize = 2;
    auto response = router.sendRequest(si, 0x54, EPath(6, 1), ForwardOpenRequest(p).pack());
    status(response, 0);
    ForwardOpenResponse opened;
    opened.expand(response.getData());
    // EIPScanner's MessageRouter convenience API is UCMM-only; use its native
    // encapsulation/CPF/request serializers for the negotiated class 3 exchange.
    for (CipUint sequence = 1; sequence <= 2; ++sequence) {
        Buffer address;
        address << opened.getO2TNetworkConnectionId();
        Buffer message;
        message << sequence << MessageRouterRequest(0x0e, EPath(1, 1, sequence == 1 ? 1 : 99), {}, true).pack();
        CommonPacket cpf;
        cpf << CommonPacketItem(CommonPacketItemIds::CONNECTION_ADDRESS_ITEM, address.data())
            << CommonPacketItem(CommonPacketItemIds::CONNECTED_TRANSPORT_PACKET, message.data());
        Buffer data;
        data << CipUdint(0) << CipUint(0) << cpf.pack();
        EncapsPacket packet;
        packet.setCommand(EncapsCommands::SEND_UNIT_DATA);
        packet.setSessionHandle(si->getSessionHandle());
        packet.setData(data.data());
        auto reply = si->sendAndReceive(packet).getData();
        require(reply.size() >= 6, "short SendUnitData reply");
        CommonPacket replyCPF;
        replyCPF.expand({reply.begin() + 6, reply.end()});
        auto body = replyCPF.getItems().at(1).getData();
        require(body.size() >= 6 && body[0] == sequence && body[1] == 0, "connected sequence lost");
        MessageRouterResponse connected;
        connected.expand({body.begin() + 2, body.end()});
        status(connected, sequence == 1 ? 0 : 0x14);
    }
    ForwardCloseRequest close;
    close.setConnectionPath(p.connectionPath);
    close.setConnectionSerialNumber(p.connectionSerialNumber);
    close.setOriginatorVendorId(p.originatorVendorId);
    close.setOriginatorSerialNumber(p.originatorSerialNumber);
    status(router.sendRequest(si, 0x4e, EPath(6, 1), close.pack()), 0);
}
static void multipleServices(const SessionInfo::SPtr& si, unsigned count) {
    std::vector<std::vector<uint8_t>> children;
    for (unsigned i = 0; i < count; ++i) {
        children.push_back(MessageRouterRequest(i == 1 ? 0x10 : 0x0e,
            EPath(i == 1 ? 4 : 1, i == 1 ? 154 : 1, i == count - 1 ? 99 : 3),
            i == 1 ? std::vector<uint8_t>(32, 0x5a) : std::vector<uint8_t>{}, true).pack());
    }
    Buffer body;
    body << CipUint(count);
    CipUint offset = 2 + 2 * count;
    for (const auto& child : children) {
        body << offset;
        offset += child.size();
    }
    for (const auto& child : children) body << child;
    auto response = MessageRouter(true).sendRequest(si, 0x0a, EPath(2, 1), body.data());
    status(response, 0x1e);
    require(!response.getData().empty(), "missing MSP child replies");
}
int main(int argc, char** argv) {
    try {
        require(argc == 3, "usage: scanner ADAPTER explicit|connected|io|msp|msp32");
        utils::Logger::setLogLevel(utils::LogLevel::INFO);
        auto si = std::make_shared<SessionInfo>(argv[1], 44818);
        std::string scenario = argv[2];
        if (scenario == "explicit") explicitMessages(si);
        else if (scenario == "connected") connectedMessages(si);
        else if (scenario == "io") implicitMessages(si);
        else if (scenario == "msp") multipleServices(si, 3);
        else if (scenario == "msp32") multipleServices(si, 32);
        else throw std::runtime_error("unknown scenario");
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "FAIL: " << e.what() << std::endl;
        return 1;
    }
}
