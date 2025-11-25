#pragma once

#include "structs.h"
#include <cstdint>

#include "asset_utils.h"

#define QRWA_CONTRACT_INDEX 18 

#define QRWA_MAX_GOV_POLLS 64
#define QRWA_MAX_ASSET_POLLS 64
#define QRWA_MAX_ASSETS 1024

#define QRWA_DONATE_TO_TREASURY 3
#define QRWA_VOTE_GOV_PARAMS 4
#define QRWA_CREATE_ASSET_RELEASE_POLL 5
#define QRWA_VOTE_ASSET_RELEASE 6
#define QRWA_DEPOSIT_GENERAL_ASSET 7

#define QRWA_GET_GOV_PARAMS 1
#define QRWA_GET_GOV_POLL 2
#define QRWA_GET_ASSET_RELEASE_POLL 3
#define QRWA_GET_TREASURY_BALANCE 4
#define QRWA_GET_DIVIDEND_BALANCES 5
#define QRWA_GET_TOTAL_DISTRIBUTED 6
#define QRWA_GET_ACTIVE_ASSET_RELEASE_POLL_IDS 7
#define QRWA_GET_ACTIVE_GOV_POLL_IDS 8


struct qRWAGovParams_cli {
    uint8_t mAdminAddress[32];
    uint8_t electricityAddress[32];
    uint8_t maintenanceAddress[32];
    uint8_t reinvestmentAddress[32];
    uint8_t qmineDevAddress[32];
    uint64_t electricityPercent;
    uint64_t maintenancePercent;
    uint64_t reinvestmentPercent;
};

struct qRWAGovProposal_cli {
    uint64_t proposalId;
    uint64_t status;
    uint64_t score;
    qRWAGovParams_cli params;
};

struct qRWAAssetReleaseProposal_cli {
    uint64_t proposalId;
    uint8_t proposalName[32];
    qpi::Asset asset;
    uint64_t amount;
    uint8_t destination[32];
    uint64_t status;
    uint64_t votesYes;
    uint64_t votesNo;
};


struct qRWADonateToTreasury_input {
    uint64_t amount;
};
struct qRWADonateToTreasury_output {
    uint64_t status;
    static constexpr unsigned char type() {
        return RespondContractFunction::type();
    }
};

struct qRWAVoteGovParams_input {
    qRWAGovParams_cli proposal;
};
struct qRWAVoteGovParams_output {
    uint64_t status;
    static constexpr unsigned char type() {
        return RespondContractFunction::type();
    }
};

struct qRWACreateAssetReleasePoll_input {
    uint8_t proposalName[32];
    qpi::Asset asset;
    uint64_t amount;
    uint8_t destination[32];
};
struct qRWACreateAssetReleasePoll_output {
    uint64_t status;
    uint64_t proposalId;
    static constexpr unsigned char type() {
        return RespondContractFunction::type();
    }
};

struct qRWAVoteAssetRelease_input {
    uint64_t proposalId;
    uint64_t option; // 0=No, 1=Yes
};
struct qRWAVoteAssetRelease_output {
    uint64_t status;
    static constexpr unsigned char type() {
        return RespondContractFunction::type();
    }
};

struct qRWADepositGeneralAsset_input {
    qpi::Asset asset;
    uint64_t amount;
};
struct qRWADepositGeneralAsset_output {
    uint64_t status;
    static constexpr unsigned char type() {
        return RespondContractFunction::type();
    }
};


struct qRWAGetGovParams_input {};
struct qRWAGetGovParams_output {
    qRWAGovParams_cli params;
    static constexpr unsigned char type() {
        return RespondContractFunction::type();
    }
};

struct qRWAGetGovPoll_input {
    uint64_t proposalId;
};
struct qRWAGetGovPoll_output {
    qRWAGovProposal_cli proposal;
    uint64_t status; // 0=NotFound, 1=Found
    static constexpr unsigned char type() {
        return RespondContractFunction::type();
    }
};

struct qRWAGetAssetReleasePoll_input {
    uint64_t proposalId;
};
struct qRWAGetAssetReleasePoll_output {
    qRWAAssetReleaseProposal_cli proposal;
    uint64_t status; // 0=NotFound, 1=Found
    static constexpr unsigned char type() {
        return RespondContractFunction::type();
    }
};

struct qRWAGetTreasuryBalance_input {};
struct qRWAGetTreasuryBalance_output {
    uint64_t balance;
    static constexpr unsigned char type() {
        return RespondContractFunction::type();
    }
};

struct qRWAGetDividendBalances_input {};
struct qRWAGetDividendBalances_output {
    uint64_t revenuePoolA;
    uint64_t revenuePoolB;
    uint64_t qmineDividendPool;
    uint64_t qrwaDividendPool;
    static constexpr unsigned char type() {
        return RespondContractFunction::type();
    }
};

struct qRWAGetTotalDistributed_input {};
struct qRWAGetTotalDistributed_output {
    uint64_t totalQmineDistributed;
    uint64_t totalQRWADistributed;
    static constexpr unsigned char type() {
        return RespondContractFunction::type();
    }
};

struct qRWAGetActiveAssetReleasePollIds_input {};
struct qRWAGetActiveAssetReleasePollIds_output
{
    uint64_t count;
    uint64_t ids[QRWA_MAX_ASSET_POLLS];
    static constexpr unsigned char type()
    {
        return RespondContractFunction::type();
    }
};

struct qRWAGetActiveGovPollIds_output
{
    uint64_t count;
    uint64_t ids[QRWA_MAX_GOV_POLLS];
    static constexpr unsigned char type()
    {
        return RespondContractFunction::type();
    }
};

void qrwaDonateToTreasury(const char* nodeIp, int nodePort, const char* seed,
    uint64_t amount, uint32_t scheduledTickOffset);

void qrwaVoteGovParams(const char* nodeIp, int nodePort, const char* seed,
    const qRWAGovParams_cli& params, uint32_t scheduledTickOffset);

void qrwaCreateAssetReleasePoll(const char* nodeIp, int nodePort, const char* seed,
    const char* proposalNameStr, const char* assetName, const char* issuerId,
    uint64_t amount, const char* destinationId, uint32_t scheduledTickOffset);

void qrwaVoteAssetRelease(const char* nodeIp, int nodePort, const char* seed,
    uint64_t proposalId, uint64_t option, uint32_t scheduledTickOffset);

void qrwaDepositGeneralAsset(const char* nodeIp, int nodePort, const char* seed,
    const char* assetName, const char* issuerId, uint64_t amount,
    uint32_t scheduledTickOffset);

void qrwaGetGovParams(const char* nodeIp, int nodePort);
void qrwaGetGovPoll(const char* nodeIp, int nodePort, uint64_t proposalId);
void qrwaGetAssetReleasePoll(const char* nodeIp, int nodePort, uint64_t proposalId);
void qrwaGetTreasuryBalance(const char* nodeIp, int nodePort);
void qrwaGetDividendBalances(const char* nodeIp, int nodePort);
void qrwaGetTotalDistributed(const char* nodeIp, int nodePort);
void qrwaGetActiveAssetReleasePollIds(const char* nodeIp, int nodePort);
void qrwaGetActiveGovPollIds(const char* nodeIp, int nodePort);
