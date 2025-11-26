#include <cstring>
#include <string>
#include <sstream>
#include <cinttypes> 

#include "qrwa.h"
#include "wallet_utils.h"
#include "node_utils.h"
#include "key_utils.h"
#include "k12_and_key_utils.h"
#include "logger.h"
#include "connection.h"
#include "structs.h"
#include "sanity_check.h"
#include "asset_utils.h"

constexpr uint64_t QRWA_REVOKE_FEE = 100;

static void printQrwaGovParams(const qRWAGovParams_cli& params) {
    char identityStr[128] = { 0 };

    getIdentityFromPublicKey(params.mAdminAddress, identityStr, false);
    LOG("  Admin Address: ........... %s\n", identityStr);

    memset(identityStr, 0, sizeof(identityStr));
    getIdentityFromPublicKey(params.electricityAddress, identityStr, false);
    LOG("  Electricity Address: ..... %s\n", identityStr);

    memset(identityStr, 0, sizeof(identityStr));
    getIdentityFromPublicKey(params.maintenanceAddress, identityStr, false);
    LOG("  Maintenance Address: ..... %s\n", identityStr);

    memset(identityStr, 0, sizeof(identityStr));
    getIdentityFromPublicKey(params.reinvestmentAddress, identityStr, false);
    LOG("  Reinvestment Address: .... %s\n", identityStr);

    memset(identityStr, 0, sizeof(identityStr));
    getIdentityFromPublicKey(params.qmineDevAddress, identityStr, false);
    LOG("  QMINE Dev Address: ....... %s\n", identityStr);

    LOG("  Electricity Percent: ..... %.1f%%\n", (double)params.electricityPercent / 10.0);
    LOG("  Maintenance Percent: ..... %.1f%%\n", (double)params.maintenancePercent / 10.0);
    LOG("  Reinvestment Percent: .... %.1f%%\n", (double)params.reinvestmentPercent / 10.0);
}

static const char* getPollStatusString(uint64_t status) {
    switch (status) {
    case 0: return "Empty";
    case 1: return "Active";
    case 2: return "Passed & Executed";
    case 3: return "Failed (Vote)";
    case 4: return "Passed (Failed Execution)";
    default: return "Unknown";
    }
}


void qrwaDonateToTreasury(const char* nodeIp, int nodePort, const char* seed,
    uint64_t amount, uint32_t scheduledTickOffset)
{
    qRWADonateToTreasury_input input;
    input.amount = amount;

    auto qc = make_qc(nodeIp, nodePort);
    if (!qc) { LOG("Failed to connect to node.\n"); return; }

    uint8_t subseed[32] = { 0 };
    uint8_t privateKey[32] = { 0 };
    uint8_t sourcePublicKey[32] = { 0 };
    uint8_t destPublicKey[32] = { 0 };
    uint8_t digest[32];
    uint8_t signature[64];
    char txHash[128] = { 0 };

    getSubseedFromSeed((uint8_t*)seed, subseed);
    getPrivateKeyFromSubSeed(subseed, privateKey);
    getPublicKeyFromPrivateKey(privateKey, sourcePublicKey);

    memset(destPublicKey, 0, 32);
    ((uint64_t*)destPublicKey)[0] = QRWA_CONTRACT_INDEX;

    struct {
        RequestResponseHeader header;
        Transaction transaction;
        qRWADonateToTreasury_input inputData;
        uint8_t sig[64];
    } packet;

    memset(&packet, 0, sizeof(packet));
    memcpy(packet.transaction.sourcePublicKey, sourcePublicKey, 32);
    memcpy(packet.transaction.destinationPublicKey, destPublicKey, 32);
    packet.transaction.amount = 0;
    uint32_t currentTick = getTickNumberFromNode(qc);
    packet.transaction.tick = currentTick + scheduledTickOffset;
    packet.transaction.inputType = QRWA_DONATE_TO_TREASURY;
    packet.transaction.inputSize = sizeof(input);
    memcpy(&packet.inputData, &input, sizeof(input));

    KangarooTwelve((uint8_t*)&packet.transaction, sizeof(packet.transaction) + sizeof(input), digest, 32);
    sign(subseed, sourcePublicKey, digest, signature);
    memcpy(packet.sig, signature, 64);

    packet.header.setSize(sizeof(packet));
    packet.header.zeroDejavu();
    packet.header.setType(BROADCAST_TRANSACTION);

    qc->sendData((uint8_t*)&packet, packet.header.size());

    KangarooTwelve((uint8_t*)&packet.transaction, sizeof(packet.transaction) + sizeof(input) + SIGNATURE_SIZE, digest, 32);
    getTxHashFromDigest(digest, txHash);

    LOG("qRWA DonateToTreasury transaction sent.\n");
    printReceipt(packet.transaction, txHash, nullptr);
    LOG("run ./qubic-cli [...] -checktxontick %u %s\n", currentTick + scheduledTickOffset, txHash);
    LOG("to check your tx confirmation status\n");
}

void qrwaVoteGovParams(const char* nodeIp, int nodePort, const char* seed,
    const qRWAGovParams_cli& params, uint32_t scheduledTickOffset)
{
    qRWAVoteGovParams_input input;
    input.proposal = params;

    auto qc = make_qc(nodeIp, nodePort);
    if (!qc) { LOG("Failed to connect to node.\n"); return; }

    uint8_t subseed[32] = { 0 };
    uint8_t privateKey[32] = { 0 };
    uint8_t sourcePublicKey[32] = { 0 };
    uint8_t destPublicKey[32] = { 0 };
    uint8_t digest[32];
    uint8_t signature[64];
    char txHash[128] = { 0 };

    getSubseedFromSeed((uint8_t*)seed, subseed);
    getPrivateKeyFromSubSeed(subseed, privateKey);
    getPublicKeyFromPrivateKey(privateKey, sourcePublicKey);

    memset(destPublicKey, 0, 32);
    ((uint64_t*)destPublicKey)[0] = QRWA_CONTRACT_INDEX;

    struct {
        RequestResponseHeader header;
        Transaction transaction;
        qRWAVoteGovParams_input inputData;
        uint8_t sig[64];
    } packet;

    memset(&packet, 0, sizeof(packet));
    memcpy(packet.transaction.sourcePublicKey, sourcePublicKey, 32);
    memcpy(packet.transaction.destinationPublicKey, destPublicKey, 32);
    packet.transaction.amount = 0;
    uint32_t currentTick = getTickNumberFromNode(qc);
    packet.transaction.tick = currentTick + scheduledTickOffset;
    packet.transaction.inputType = QRWA_VOTE_GOV_PARAMS;
    packet.transaction.inputSize = sizeof(input);
    memcpy(&packet.inputData, &input, sizeof(input));

    KangarooTwelve((uint8_t*)&packet.transaction, sizeof(packet.transaction) + sizeof(input), digest, 32);
    sign(subseed, sourcePublicKey, digest, signature);
    memcpy(packet.sig, signature, 64);

    packet.header.setSize(sizeof(packet));
    packet.header.zeroDejavu();
    packet.header.setType(BROADCAST_TRANSACTION);

    qc->sendData((uint8_t*)&packet, packet.header.size());

    KangarooTwelve((uint8_t*)&packet.transaction, sizeof(packet.transaction) + sizeof(input) + SIGNATURE_SIZE, digest, 32);
    getTxHashFromDigest(digest, txHash);

    LOG("qRWA VoteGovParams transaction sent.\n");
    printReceipt(packet.transaction, txHash, nullptr);
    LOG("run ./qubic-cli [...] -checktxontick %u %s\n", currentTick + scheduledTickOffset, txHash);
    LOG("to check your tx confirmation status\n");
}

void qrwaCreateAssetReleasePoll(const char* nodeIp, int nodePort, const char* seed,
    const char* proposalNameStr, const char* assetName, const char* issuerId,
    uint64_t amount, const char* destinationId, uint32_t scheduledTickOffset)
{
    qRWACreateAssetReleasePoll_input input;
    memset(&input, 0, sizeof(input));

    size_t len = strlen(proposalNameStr);
    if (len > 32) len = 32;
    memcpy(input.proposalName, proposalNameStr, len);

    input.asset.assetName = assetNameFromString(assetName);
    getPublicKeyFromIdentity(issuerId, input.asset.issuer);

    input.amount = amount;
    getPublicKeyFromIdentity(destinationId, input.destination);

    auto qc = make_qc(nodeIp, nodePort);
    if (!qc) { LOG("Failed to connect to node.\n"); return; }

    uint8_t subseed[32] = { 0 };
    uint8_t privateKey[32] = { 0 };
    uint8_t sourcePublicKey[32] = { 0 };
    uint8_t destPublicKey[32] = { 0 };
    uint8_t digest[32];
    uint8_t signature[64];
    char txHash[128] = { 0 };

    getSubseedFromSeed((uint8_t*)seed, subseed);
    getPrivateKeyFromSubSeed(subseed, privateKey);
    getPublicKeyFromPrivateKey(privateKey, sourcePublicKey);

    memset(destPublicKey, 0, 32);
    ((uint64_t*)destPublicKey)[0] = QRWA_CONTRACT_INDEX;

    struct {
        RequestResponseHeader header;
        Transaction transaction;
        qRWACreateAssetReleasePoll_input inputData;
        uint8_t sig[64];
    } packet;

    memset(&packet, 0, sizeof(packet));
    memcpy(packet.transaction.sourcePublicKey, sourcePublicKey, 32);
    memcpy(packet.transaction.destinationPublicKey, destPublicKey, 32);
    packet.transaction.amount = 0;
    uint32_t currentTick = getTickNumberFromNode(qc);
    packet.transaction.tick = currentTick + scheduledTickOffset;
    packet.transaction.inputType = QRWA_CREATE_ASSET_RELEASE_POLL;
    packet.transaction.inputSize = sizeof(input);
    memcpy(&packet.inputData, &input, sizeof(input));

    KangarooTwelve((uint8_t*)&packet.transaction, sizeof(packet.transaction) + sizeof(input), digest, 32);
    sign(subseed, sourcePublicKey, digest, signature);
    memcpy(packet.sig, signature, 64);

    packet.header.setSize(sizeof(packet));
    packet.header.zeroDejavu();
    packet.header.setType(BROADCAST_TRANSACTION);

    qc->sendData((uint8_t*)&packet, packet.header.size());

    KangarooTwelve((uint8_t*)&packet.transaction, sizeof(packet.transaction) + sizeof(input) + SIGNATURE_SIZE, digest, 32);
    getTxHashFromDigest(digest, txHash);

    LOG("qRWA CreateAssetReleasePoll transaction sent.\n");
    printReceipt(packet.transaction, txHash, nullptr);
    LOG("run ./qubic-cli [...] -checktxontick %u %s\n", currentTick + scheduledTickOffset, txHash);
    LOG("to check your tx confirmation status\n");
}

void qrwaVoteAssetRelease(const char* nodeIp, int nodePort, const char* seed,
    uint64_t proposalId, uint64_t option, uint32_t scheduledTickOffset)
{
    qRWAVoteAssetRelease_input input;
    input.proposalId = proposalId;
    input.option = option;

    auto qc = make_qc(nodeIp, nodePort);
    if (!qc) { LOG("Failed to connect to node.\n"); return; }

    uint8_t subseed[32] = { 0 };
    uint8_t privateKey[32] = { 0 };
    uint8_t sourcePublicKey[32] = { 0 };
    uint8_t destPublicKey[32] = { 0 };
    uint8_t digest[32];
    uint8_t signature[64];
    char txHash[128] = { 0 };

    getSubseedFromSeed((uint8_t*)seed, subseed);
    getPrivateKeyFromSubSeed(subseed, privateKey);
    getPublicKeyFromPrivateKey(privateKey, sourcePublicKey);

    memset(destPublicKey, 0, 32);
    ((uint64_t*)destPublicKey)[0] = QRWA_CONTRACT_INDEX;

    struct {
        RequestResponseHeader header;
        Transaction transaction;
        qRWAVoteAssetRelease_input inputData;
        uint8_t sig[64];
    } packet;

    memset(&packet, 0, sizeof(packet));
    memcpy(packet.transaction.sourcePublicKey, sourcePublicKey, 32);
    memcpy(packet.transaction.destinationPublicKey, destPublicKey, 32);
    packet.transaction.amount = 0;
    uint32_t currentTick = getTickNumberFromNode(qc);
    packet.transaction.tick = currentTick + scheduledTickOffset;
    packet.transaction.inputType = QRWA_VOTE_ASSET_RELEASE;
    packet.transaction.inputSize = sizeof(input);
    memcpy(&packet.inputData, &input, sizeof(input));

    KangarooTwelve((uint8_t*)&packet.transaction, sizeof(packet.transaction) + sizeof(input), digest, 32);
    sign(subseed, sourcePublicKey, digest, signature);
    memcpy(packet.sig, signature, 64);

    packet.header.setSize(sizeof(packet));
    packet.header.zeroDejavu();
    packet.header.setType(BROADCAST_TRANSACTION);

    qc->sendData((uint8_t*)&packet, packet.header.size());

    KangarooTwelve((uint8_t*)&packet.transaction, sizeof(packet.transaction) + sizeof(input) + SIGNATURE_SIZE, digest, 32);
    getTxHashFromDigest(digest, txHash);

    LOG("qRWA VoteAssetRelease transaction sent.\n");
    printReceipt(packet.transaction, txHash, nullptr);
    LOG("run ./qubic-cli [...] -checktxontick %u %s\n", currentTick + scheduledTickOffset, txHash);
    LOG("to check your tx confirmation status\n");
}

void qrwaDepositGeneralAsset(const char* nodeIp, int nodePort, const char* seed,
    const char* assetName, const char* issuerId, uint64_t amount,
    uint32_t scheduledTickOffset)
{
    qRWADepositGeneralAsset_input input;
    memset(&input, 0, sizeof(input));

    input.asset.assetName = assetNameFromString(assetName);
    getPublicKeyFromIdentity(issuerId, input.asset.issuer);
    input.amount = amount;

    auto qc = make_qc(nodeIp, nodePort);
    if (!qc) { LOG("Failed to connect to node.\n"); return; }

    uint8_t subseed[32] = { 0 };
    uint8_t privateKey[32] = { 0 };
    uint8_t sourcePublicKey[32] = { 0 };
    uint8_t destPublicKey[32] = { 0 };
    uint8_t digest[32];
    uint8_t signature[64];
    char txHash[128] = { 0 };

    getSubseedFromSeed((uint8_t*)seed, subseed);
    getPrivateKeyFromSubSeed(subseed, privateKey);
    getPublicKeyFromPrivateKey(privateKey, sourcePublicKey);

    memset(destPublicKey, 0, 32);
    ((uint64_t*)destPublicKey)[0] = QRWA_CONTRACT_INDEX;

    struct {
        RequestResponseHeader header;
        Transaction transaction;
        qRWADepositGeneralAsset_input inputData;
        uint8_t sig[64];
    } packet;

    memset(&packet, 0, sizeof(packet));
    memcpy(packet.transaction.sourcePublicKey, sourcePublicKey, 32);
    memcpy(packet.transaction.destinationPublicKey, destPublicKey, 32);
    packet.transaction.amount = 0;
    uint32_t currentTick = getTickNumberFromNode(qc);
    packet.transaction.tick = currentTick + scheduledTickOffset;
    packet.transaction.inputType = QRWA_DEPOSIT_GENERAL_ASSET;
    packet.transaction.inputSize = sizeof(input);
    memcpy(&packet.inputData, &input, sizeof(input));

    KangarooTwelve((uint8_t*)&packet.transaction, sizeof(packet.transaction) + sizeof(input), digest, 32);
    sign(subseed, sourcePublicKey, digest, signature);
    memcpy(packet.sig, signature, 64);

    packet.header.setSize(sizeof(packet));
    packet.header.zeroDejavu();
    packet.header.setType(BROADCAST_TRANSACTION);

    qc->sendData((uint8_t*)&packet, packet.header.size());

    KangarooTwelve((uint8_t*)&packet.transaction, sizeof(packet.transaction) + sizeof(input) + SIGNATURE_SIZE, digest, 32);
    getTxHashFromDigest(digest, txHash);

    LOG("qRWA DepositGeneralAsset transaction sent.\n");
    printReceipt(packet.transaction, txHash, nullptr);
    LOG("run ./qubic-cli [...] -checktxontick %u %s\n", currentTick + scheduledTickOffset, txHash);
    LOG("to check your tx confirmation status\n");
}

void qrwaRevokeAssetManagementRights(const char* nodeIp, int nodePort, const char* seed,
    const char* assetName, const char* issuerId, int64_t numberOfShares,
    uint32_t scheduledTickOffset)
{
    auto qc = make_qc(nodeIp, nodePort);
    if (!qc) { LOG("Failed to connect to node.\n"); return; }

    qRWARevokeAssetManagementRights_input input;
    memset(&input, 0, sizeof(input));
    input.asset.assetName = assetNameFromString(assetName);
    getPublicKeyFromIdentity(issuerId, input.asset.issuer);
    input.numberOfShares = numberOfShares;

    uint8_t subseed[32] = { 0 };
    uint8_t privateKey[32] = { 0 };
    uint8_t sourcePublicKey[32] = { 0 };
    uint8_t destPublicKey[32] = { 0 };
    uint8_t digest[32];
    uint8_t signature[64];
    char txHash[128] = { 0 };

    getSubseedFromSeed((uint8_t*)seed, subseed);
    getPrivateKeyFromSubSeed(subseed, privateKey);
    getPublicKeyFromPrivateKey(privateKey, sourcePublicKey);

    memset(destPublicKey, 0, 32);
    ((uint64_t*)destPublicKey)[0] = QRWA_CONTRACT_INDEX;

    struct {
        RequestResponseHeader header;
        Transaction transaction;
        qRWARevokeAssetManagementRights_input inputData;
        uint8_t sig[64];
    } packet;

    memset(&packet, 0, sizeof(packet));
    memcpy(packet.transaction.sourcePublicKey, sourcePublicKey, 32);
    memcpy(packet.transaction.destinationPublicKey, destPublicKey, 32);
    packet.transaction.amount = QRWA_REVOKE_FEE;
    uint32_t currentTick = getTickNumberFromNode(qc);
    packet.transaction.tick = currentTick + scheduledTickOffset;
    packet.transaction.inputType = QRWA_REVOKE_ASSET_MANAGEMENT_RIGHTS;
    packet.transaction.inputSize = sizeof(input);
    memcpy(&packet.inputData, &input, sizeof(input));

    KangarooTwelve((uint8_t*)&packet.transaction, sizeof(packet.transaction) + sizeof(input), digest, 32);
    sign(subseed, sourcePublicKey, digest, signature);
    memcpy(packet.sig, signature, 64);

    packet.header.setSize(sizeof(packet));
    packet.header.zeroDejavu();
    packet.header.setType(BROADCAST_TRANSACTION);

    qc->sendData((uint8_t*)&packet, packet.header.size());

    KangarooTwelve((uint8_t*)&packet.transaction, sizeof(packet.transaction) + sizeof(input) + SIGNATURE_SIZE, digest, 32);
    getTxHashFromDigest(digest, txHash);

    LOG("qRWA RevokeAssetManagementRights transaction sent.\n");
    printReceipt(packet.transaction, txHash, nullptr);
    LOG("run ./qubic-cli [...] -checktxontick %u %s\n", currentTick + scheduledTickOffset, txHash);
    LOG("to check your tx confirmation status\n");
}

void qrwaGetGovParams(const char* nodeIp, int nodePort)
{
    auto qc = make_qc(nodeIp, nodePort);
    if (!qc) { LOG("Failed to connect to node.\n"); return; }

    struct {
        RequestResponseHeader header;
        RequestContractFunction rcf;
    } req;

    memset(&req, 0, sizeof(req));
    req.rcf.contractIndex = QRWA_CONTRACT_INDEX;
    req.rcf.inputType = QRWA_GET_GOV_PARAMS;
    req.rcf.inputSize = 0;
    req.header.setSize(sizeof(req.header) + sizeof(req.rcf));
    req.header.randomizeDejavu();
    req.header.setType(RequestContractFunction::type());

    qc->sendData((uint8_t*)&req, req.header.size());

    qRWAGetGovParams_output output;
    memset(&output, 0, sizeof(output));
    try {
        output = qc->receivePacketWithHeaderAs<qRWAGetGovParams_output>();
    }
    catch (std::logic_error& e) {
        LOG("Failed to get governance parameters: %s\n", e.what());
        return;
    }

    LOG("Current qRWA Governance Parameters:\n");
    printQrwaGovParams(output.params);
}

void qrwaGetGovPoll(const char* nodeIp, int nodePort, uint64_t proposalId)
{
    auto qc = make_qc(nodeIp, nodePort);
    if (!qc) { LOG("Failed to connect to node.\n"); return; }

    qRWAGetGovPoll_input input;
    input.proposalId = proposalId;

    struct {
        RequestResponseHeader header;
        RequestContractFunction rcf;
        qRWAGetGovPoll_input in;
    } req;

    memset(&req, 0, sizeof(req));
    req.rcf.contractIndex = QRWA_CONTRACT_INDEX;
    req.rcf.inputType = QRWA_GET_GOV_POLL;
    req.rcf.inputSize = sizeof(input);
    memcpy(&req.in, &input, sizeof(input));
    req.header.setSize(sizeof(req.header) + sizeof(req.rcf) + sizeof(input));
    req.header.randomizeDejavu();
    req.header.setType(RequestContractFunction::type());

    qc->sendData((uint8_t*)&req, req.header.size());

    qRWAGetGovPoll_output output;
    memset(&output, 0, sizeof(output));
    try {
        output = qc->receivePacketWithHeaderAs<qRWAGetGovPoll_output>();
    }
    catch (std::logic_error& e) {
        LOG("Failed to get governance poll: %s\n", e.what());
        return;
    }

    if (output.status == 0) {
        LOG("Governance poll with ID %" PRIu64 " not found.\n", proposalId);
        return;
    }

    LOG("Governance Poll Details (ID: %" PRIu64 "):\n", output.proposal.proposalId);
    LOG("  Status: ................... %s (%" PRIu64 ")\n", getPollStatusString(output.proposal.status), output.proposal.status);
    LOG("  Final Score: ............ %" PRIu64 "\n", output.proposal.score);
    LOG("  Proposed Parameters:\n");
    printQrwaGovParams(output.proposal.params);
}

void qrwaGetAssetReleasePoll(const char* nodeIp, int nodePort, uint64_t proposalId)
{
    auto qc = make_qc(nodeIp, nodePort);
    if (!qc) { LOG("Failed to connect to node.\n"); return; }

    qRWAGetAssetReleasePoll_input input;
    input.proposalId = proposalId;

    struct {
        RequestResponseHeader header;
        RequestContractFunction rcf;
        qRWAGetAssetReleasePoll_input in;
    } req;

    memset(&req, 0, sizeof(req));
    req.rcf.contractIndex = QRWA_CONTRACT_INDEX;
    req.rcf.inputType = QRWA_GET_ASSET_RELEASE_POLL;
    req.rcf.inputSize = sizeof(input);
    memcpy(&req.in, &input, sizeof(input));
    req.header.setSize(sizeof(req.header) + sizeof(req.rcf) + sizeof(input));
    req.header.randomizeDejavu();
    req.header.setType(RequestContractFunction::type());

    qc->sendData((uint8_t*)&req, req.header.size());

    qRWAGetAssetReleasePoll_output output;
    memset(&output, 0, sizeof(output));
    try {
        output = qc->receivePacketWithHeaderAs<qRWAGetAssetReleasePoll_output>();
    }
    catch (std::logic_error& e) {
        LOG("Failed to get asset release poll: %s\n", e.what());
        return;
    }

    if (output.status == 0) {
        LOG("Asset release poll with ID %" PRIu64 " not found.\n", proposalId);
        return;
    }

    LOG("Asset Release Poll Details (ID: %" PRIu64 "):\n", output.proposal.proposalId);

    char proposalNameStr[33] = { 0 };
    memcpy(proposalNameStr, output.proposal.proposalName, 32);
    LOG("  Name: ..................... %s\n", proposalNameStr);

    char issuerStr[128] = { 0 };
    char assetNameStr[8] = { 0 };
    getIdentityFromPublicKey(output.proposal.asset.issuer, issuerStr, false);
    assetNameToString(output.proposal.asset.assetName, assetNameStr);
    LOG("  Asset: .................... %s (by %s)\n", assetNameStr, issuerStr);

    LOG("  Amount: ................... %" PRIu64 "\n", output.proposal.amount);

    char destStr[128] = { 0 };
    getIdentityFromPublicKey(output.proposal.destination, destStr, false);
    LOG("  Destination: .............. %s\n", destStr);

    LOG("  Status: ................... %s (%" PRIu64 ")\n", getPollStatusString(output.proposal.status), output.proposal.status);
    LOG("  Votes (Yes): .............. %" PRIu64 "\n", output.proposal.votesYes);
    LOG("  Votes (No): ............... %" PRIu64 "\n", output.proposal.votesNo);
}

void qrwaGetTreasuryBalance(const char* nodeIp, int nodePort)
{
    auto qc = make_qc(nodeIp, nodePort);
    if (!qc) { LOG("Failed to connect to node.\n"); return; }

    struct {
        RequestResponseHeader header;
        RequestContractFunction rcf;
    } req;

    memset(&req, 0, sizeof(req));
    req.rcf.contractIndex = QRWA_CONTRACT_INDEX;
    req.rcf.inputType = QRWA_GET_TREASURY_BALANCE;
    req.rcf.inputSize = 0;
    req.header.setSize(sizeof(req.header) + sizeof(req.rcf));
    req.header.randomizeDejavu();
    req.header.setType(RequestContractFunction::type());

    qc->sendData((uint8_t*)&req, req.header.size());

    qRWAGetTreasuryBalance_output output;
    memset(&output, 0, sizeof(output));
    try {
        output = qc->receivePacketWithHeaderAs<qRWAGetTreasuryBalance_output>();
    }
    catch (std::logic_error& e) {
        LOG("Failed to get treasury balance: %s\n", e.what());
        return;
    }

    LOG("qRWA QMINE Treasury Balance: %" PRIu64 "\n", output.balance);
}

void qrwaGetDividendBalances(const char* nodeIp, int nodePort)
{
    auto qc = make_qc(nodeIp, nodePort);
    if (!qc) { LOG("Failed to connect to node.\n"); return; }

    struct {
        RequestResponseHeader header;
        RequestContractFunction rcf;
    } req;

    memset(&req, 0, sizeof(req));
    req.rcf.contractIndex = QRWA_CONTRACT_INDEX;
    req.rcf.inputType = QRWA_GET_DIVIDEND_BALANCES;
    req.rcf.inputSize = 0;
    req.header.setSize(sizeof(req.header) + sizeof(req.rcf));
    req.header.randomizeDejavu();
    req.header.setType(RequestContractFunction::type());

    qc->sendData((uint8_t*)&req, req.header.size());

    qRWAGetDividendBalances_output output;
    memset(&output, 0, sizeof(output));
    try {
        output = qc->receivePacketWithHeaderAs<qRWAGetDividendBalances_output>();
    }
    catch (std::logic_error& e) {
        LOG("Failed to get dividend balances: %s\n", e.what());
        return;
    }

    LOG("qRWA Dividend Pool Balances:\n");
    LOG("  Revenue Pool A (Mined): .... %" PRIu64 "\n", output.revenuePoolA);
    LOG("  Revenue Pool B (Other): .... %" PRIu64 "\n", output.revenuePoolB);
    LOG("  QMINE Dividend Pool: ....... %" PRIu64 "\n", output.qmineDividendPool);
    LOG("  qRWA Dividend Pool: ........ %" PRIu64 "\n", output.qrwaDividendPool);
}

void qrwaGetTotalDistributed(const char* nodeIp, int nodePort)
{
    auto qc = make_qc(nodeIp, nodePort);
    if (!qc) { LOG("Failed to connect to node.\n"); return; }

    struct {
        RequestResponseHeader header;
        RequestContractFunction rcf;
    } req;

    memset(&req, 0, sizeof(req));
    req.rcf.contractIndex = QRWA_CONTRACT_INDEX;
    req.rcf.inputType = QRWA_GET_TOTAL_DISTRIBUTED;
    req.rcf.inputSize = 0;
    req.header.setSize(sizeof(req.header) + sizeof(req.rcf));
    req.header.randomizeDejavu();
    req.header.setType(RequestContractFunction::type());

    qc->sendData((uint8_t*)&req, req.header.size());

    qRWAGetTotalDistributed_output output;
    memset(&output, 0, sizeof(output));
    try {
        output = qc->receivePacketWithHeaderAs<qRWAGetTotalDistributed_output>();
    }
    catch (std::logic_error& e) {
        LOG("Failed to get total distributed: %s\n", e.what());
        return;
    }

    LOG("qRWA Total Distributed Dividends:\n");
    LOG("  Total to QMINE Holders: .... %" PRIu64 "\n", output.totalQmineDistributed);
    LOG("  Total to qRWA Shareholders:  %" PRIu64 "\n", output.totalQRWADistributed);
}

void qrwaGetActiveAssetReleasePollIds(const char* nodeIp, int nodePort)
{
    auto qc = make_qc(nodeIp, nodePort);
    if (!qc)
    {
        LOG("Failed to connect to node.\n"); return;
    }

    struct
    {
        RequestResponseHeader header;
        RequestContractFunction rcf;
    } req;

    memset(&req, 0, sizeof(req));
    req.rcf.contractIndex = QRWA_CONTRACT_INDEX;
    req.rcf.inputType = QRWA_GET_ACTIVE_ASSET_RELEASE_POLL_IDS;
    req.rcf.inputSize = 0;

    req.header.setSize(sizeof(req.header) + sizeof(req.rcf));
    req.header.randomizeDejavu();
    req.header.setType(RequestContractFunction::type());

    qc->sendData((uint8_t*)&req, req.header.size());

    qRWAGetActiveAssetReleasePollIds_output output;
    memset(&output, 0, sizeof(output));

    try
    {
        output = qc->receivePacketWithHeaderAs<qRWAGetActiveAssetReleasePollIds_output>();
    }
    catch (std::logic_error& e)
    {
        LOG("Failed to get active asset release poll IDs: %s\n", e.what());
        return;
    }

    LOG("Active Asset Release Polls (% " PRIu64 " found):\n", output.count);
    for (uint64_t i = 0; i < output.count; i++)
    {
        LOG(" - Proposal ID: %" PRIu64 "\n", output.ids[i]);
    }
}

void qrwaGetActiveGovPollIds(const char* nodeIp, int nodePort)
{
    auto qc = make_qc(nodeIp, nodePort);
    if (!qc)
    {
        LOG("Failed to connect to node.\n"); return;
    }

    struct
    {
        RequestResponseHeader header;
        RequestContractFunction rcf;
    } req;

    memset(&req, 0, sizeof(req));
    req.rcf.contractIndex = QRWA_CONTRACT_INDEX;
    req.rcf.inputType = QRWA_GET_ACTIVE_GOV_POLL_IDS;
    req.rcf.inputSize = 0;

    req.header.setSize(sizeof(req.header) + sizeof(req.rcf));
    req.header.randomizeDejavu();
    req.header.setType(RequestContractFunction::type());

    qc->sendData((uint8_t*)&req, req.header.size());

    qRWAGetActiveGovPollIds_output output;
    memset(&output, 0, sizeof(output));

    try
    {
        output = qc->receivePacketWithHeaderAs<qRWAGetActiveGovPollIds_output>();
    }
    catch (std::logic_error& e)
    {
        LOG("Failed to get active governance poll IDs: %s\n", e.what());
        return;
    }

    LOG("Active Governance Polls (% " PRIu64 " found):\n", output.count);
    for (uint64_t i = 0; i < output.count; i++)
    {
        LOG(" - Proposal ID: %" PRIu64 "\n", output.ids[i]);
    }
}

void qrwaGetGeneralAssetBalance(const char* nodeIp, int nodePort, const char* assetName, const char* issuerId)
{
    auto qc = make_qc(nodeIp, nodePort);
    if (!qc) { LOG("Failed to connect to node.\n"); return; }

    qRWAGetGeneralAssetBalance_input input;
    memset(&input, 0, sizeof(input));

    input.asset.assetName = assetNameFromString(assetName);
    getPublicKeyFromIdentity(issuerId, input.asset.issuer);

    struct {
        RequestResponseHeader header;
        RequestContractFunction rcf;
        qRWAGetGeneralAssetBalance_input in;
    } req;

    memset(&req, 0, sizeof(req));
    req.rcf.contractIndex = QRWA_CONTRACT_INDEX;
    req.rcf.inputType = QRWA_GET_GENERAL_ASSET_BALANCE;
    req.rcf.inputSize = sizeof(input);
    memcpy(&req.in, &input, sizeof(input));

    req.header.setSize(sizeof(req.header) + sizeof(req.rcf) + sizeof(input));
    req.header.randomizeDejavu();
    req.header.setType(RequestContractFunction::type());

    qc->sendData((uint8_t*)&req, req.header.size());

    qRWAGetGeneralAssetBalance_output output;
    memset(&output, 0, sizeof(output));
    try {
        output = qc->receivePacketWithHeaderAs<qRWAGetGeneralAssetBalance_output>();
    }
    catch (std::logic_error& e) {
        LOG("Failed to get general asset balance: %s\n", e.what());
        return;
    }

    if (output.status == 1)
    {
        LOG("General Asset Balance for %s (Issuer: %s): %" PRIu64 "\n", assetName, issuerId, output.balance);
    }
    else
    {
        LOG("Asset %s (Issuer: %s) not found in qRWA General Assets.\n", assetName, issuerId);
    }
}

void qrwaGetGeneralAssets(const char* nodeIp, int nodePort)
{
    auto qc = make_qc(nodeIp, nodePort);
    if (!qc)
    {
        LOG("Failed to connect to node.\n"); return;
    }

    struct
    {
        RequestResponseHeader header;
        RequestContractFunction rcf;
        qRWAGetGeneralAssets_input in;
    } req;

    memset(&req, 0, sizeof(req));
    req.rcf.contractIndex = QRWA_CONTRACT_INDEX;
    req.rcf.inputType = QRWA_GET_GENERAL_ASSETS;
    req.rcf.inputSize = 0;

    req.header.setSize(sizeof(req.header) + sizeof(req.rcf));
    req.header.randomizeDejavu();
    req.header.setType(RequestContractFunction::type());

    qc->sendData((uint8_t*)&req, req.header.size());

    qRWAGetGeneralAssets_output output;
    memset(&output, 0, sizeof(output));
    try
    {
        output = qc->receivePacketWithHeaderAs<qRWAGetGeneralAssets_output>();
    }
    catch (std::logic_error& e)
    {
        LOG("Failed to get general assets: %s\n", e.what());
        return;
    }

    LOG("General Assets held by qRWA (%llu found):\n", (unsigned long long)output.count);

    for (uint64_t i = 0; i < output.count; i++)
    {
        char assetNameStr[8] = { 0 };
        char issuerStr[128] = { 0 };

        assetNameToString(output.assets[i].assetName, assetNameStr);
        getIdentityFromPublicKey(output.assets[i].issuer, issuerStr, false);

        LOG("  %d. Asset: %s | Issuer: %s | Balance: %" PRIu64 "\n",
            (int)(i + 1),
            assetNameStr,
            issuerStr,
            output.balances[i]);
    }
}
