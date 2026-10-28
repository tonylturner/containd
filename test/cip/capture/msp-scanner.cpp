// SPDX-License-Identifier: Apache-2.0
// EIPScanner requests; only the unmodified cpppo adapter produces replies.
#include <iostream>
#include <stdexcept>
#include <string>
#include "SessionInfo.h"
#include "MessageRouter.h"
#include "cip/MessageRouterRequest.h"
#include "utils/Buffer.h"

using namespace eipScanner;
using namespace eipScanner::cip;
using eipScanner::utils::Buffer;

static void require(bool ok, const std::string& message) {
    if (!ok) throw std::runtime_error(message);
}
static unsigned word(const std::vector<uint8_t>& data, unsigned pos) {
    return data.at(pos) | (unsigned(data.at(pos + 1)) << 8);
}
int main(int argc, char** argv) {
    try {
        require(argc == 3, "usage: msp-scanner ADAPTER msp|msp32|msp-error");
        const std::string scenario = argv[2];
        require(scenario == "msp" || scenario == "msp32" || scenario == "msp-error", "unknown scenario");
        const bool failure = scenario == "msp-error";
        const unsigned count = scenario == "msp32" ? 32 : 3;
        std::vector<std::vector<uint8_t>> children;
        for (unsigned i = 0; i < count; ++i) {
            children.push_back(MessageRouterRequest(i == 1 ? 0x10 : 0x0e,
                EPath(0x6b, 1, failure && i == count - 1 ? 99 : 1),
                i == 1 ? std::vector<uint8_t>{1, 0, 2, 0, 3, 0, 4, 0} : std::vector<uint8_t>{}, true).pack());
        }
        Buffer body;
        body << CipUint(count);
        CipUint offset = 2 + 2 * count;
        for (const auto& child : children) {
            body << offset;
            offset += child.size();
        }
        for (const auto& child : children) body << child;
        auto si = std::make_shared<SessionInfo>(argv[1], 44818);
        auto reply = MessageRouter(true).sendRequest(si, 0x0a, EPath(2, 1), body.data());
        const auto& data = reply.getData();
        require(word(data, 0) == count, "MSP reply lost children");
        unsigned failed = 0;
        for (unsigned i = 0; i < count; ++i) {
            const unsigned start = word(data, 2 + 2 * i);
            const unsigned end = i + 1 < count ? word(data, 4 + 2 * i) : data.size();
            require(start < end && end <= data.size(), "invalid MSP response offset");
            MessageRouterResponse child;
            child.expand({data.begin() + start, data.begin() + end});
            const auto status = static_cast<unsigned>(child.getGeneralStatusCode());
            std::cout << "child[" << i << "] status=0x" << std::hex << status << std::dec << std::endl;
            if (status) ++failed;
        }
        const unsigned wrapper = static_cast<unsigned>(reply.getGeneralStatusCode());
        std::cout << "wrapper status=0x" << std::hex << wrapper << std::dec
                  << " children=" << count << " failed=" << failed << std::endl;
        require(failed == (failure ? 1U : 0U), "unexpected real child failures");
        require(wrapper == (failure ? 0x1eU : 0U), "MSP wrapper must report embedded service error 0x1e when a child fails");
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << std::endl;
        return 1;
    }
}
