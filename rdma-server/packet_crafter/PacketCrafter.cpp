#include "PacketCrafter.h"

PacketCrafter::PacketCrafter() {
    this->logger = spdlog::stdout_logger_mt("PacketCrafter");
}

PacketCrafter::~PacketCrafter() {
    spdlog::drop("PacketCrafter");
}

void PacketCrafter::sendRDMAInfoPacket(void *payload, uint8_t length, const std::string &iface) {
    this->logger->info("Building rdma_info packet for switch...");

    Crafter::Ethernet ethernet;
    ethernet.SetSourceMAC("00:00:00:00:00:01");
    ethernet.SetDestinationMAC("00:00:00:00:00:02");
    ethernet.SetType(0x1234);

    Crafter::RawLayer rdmaInfo;
    rdmaInfo.AddPayload((uint8_t *) payload, length);

    Crafter::Packet packet(ethernet / rdmaInfo);

    this->logger->info("Sending packet from interface {0}", iface);

    packet.Send(iface);
}