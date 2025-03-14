// Licensed under the Apache-2.0 license
#pragma once

#include <stdint.h>
#include <stdbool.h>

#include "caliptra_enums.h"

typedef uint32_t caliptra_checksum;

/**
 * caliptra_buffer
 *
 * Transfer buffer for Caliptra mailbox commands
 */
#if !defined(HWMODEL)
typedef struct caliptra_buffer {
  const uint8_t *data; //< Pointer to a buffer with data to send/space to receive
  uintptr_t len;       //< Size of the buffer
} caliptra_buffer;
#endif

/**
 * caliptra_fuses
 *
 * Fuse data to be written to Caliptra registers
 */
struct caliptra_fuses {
    uint32_t uds_seed[12];
    uint32_t field_entropy[8];
    uint32_t key_manifest_pk_hash[12];
    uint32_t key_manifest_pk_hash_mask : 4;
    uint32_t rsvd : 28;
    uint32_t owner_pk_hash[12];
    uint32_t fmc_key_manifest_svn;
    uint32_t runtime_svn[4];
    bool anti_rollback_disable;
    uint32_t idevid_cert_attr[24];
    uint32_t idevid_manuf_hsm_id[4];
    enum device_lifecycle life_cycle;
    bool lms_verify;
    uint32_t lms_revocation;
    uint16_t soc_stepping_id;
};

//    Request/Response fields

struct caliptra_req_header {
    caliptra_checksum chksum;
};

struct caliptra_resp_header {
    caliptra_checksum chksum;
    uint32_t fips_status;
};

struct caliptra_get_idev_cert_req {
    struct caliptra_req_header hdr;
    uint32_t tbs_size;
    uint8_t signature_r[48];
    uint8_t signature_s[48];
    uint8_t tbs[916];
};

struct caliptra_get_idev_cert_resp {
    struct caliptra_resp_header hdr;
    uint32_t cert_size;
    uint8_t cert[1024];
};

struct caliptra_get_idev_info_resp {
    struct caliptra_resp_header hdr;
    uint8_t idev_pub_x[48];
    uint8_t idev_pub_y[48];
};

struct caliptra_populate_idev_cert_req {
    struct caliptra_req_header hdr;
    uint32_t cert_size;
    uint8_t cert[1024];
};

struct caliptra_get_ldev_cert_resp {
    struct caliptra_resp_header hdr;
    uint32_t data_size;
    uint8_t data[1024];
};

struct caliptra_get_fmc_alias_cert_resp {
    struct caliptra_resp_header hdr;
    uint32_t data_size;
    uint8_t data[1024];
};

struct caliptra_get_rt_alias_cert_resp {
    struct caliptra_resp_header hdr;
    uint32_t data_size;
    uint8_t data[1024];
};

struct caliptra_ecdsa_verify_req {
    struct caliptra_req_header hdr;
    uint8_t pub_key_x[48];
    uint8_t pub_key_y[48];
    uint8_t signature_r[48];
    uint8_t signature_s[48];
};

struct caliptra_stash_measurement_req {
    struct caliptra_req_header hdr;
    uint8_t metadata[4];
    uint8_t measurement[48];
    uint8_t context[48];
    uint32_t svn;
};

struct caliptra_stash_measurement_resp {
    struct caliptra_resp_header hdr;
    uint32_t dpe_result;
};

struct caliptra_fw_info_resp {
    struct caliptra_resp_header hdr;
    uint32_t pl0_pauser;
    uint32_t runtime_svn;
    uint32_t min_runtime_svn;
    uint32_t fmc_manifest_svn;
    uint32_t attestation_disabled;
    uint8_t rom_revision[20];
    uint8_t fmc_revision[20];
    uint8_t runtime_revision[20];
    uint32_t rom_sha256_digest[8];
    uint32_t fmc_sha384_digest[12];
    uint32_t runtime_sha384_digest[12];
};

struct caliptra_dpe_tag_tci_req {
    struct caliptra_req_header hdr;
    uint8_t handle[16];
    uint32_t tag;
};

struct caliptra_get_tagged_tci_req {
    struct caliptra_req_header hdr;
    uint32_t tag;
};

struct caliptra_get_tagged_tci_resp {
    struct caliptra_resp_header hdr;
    uint8_t tci_cumulative[48];
    uint8_t tci_current[48];
};

struct caliptra_fips_version_resp {
    struct caliptra_resp_header hdr;
    uint32_t mode;
    uint32_t fips_rev[3];
    uint8_t name[12];
};

struct caliptra_capabilities_resp {
    struct caliptra_resp_header hdr;
    uint8_t capabilities[16];
};

// The below fields are placeholders to set up the baseline
// required for communication of DPE commands to Caliptra
// firmware.

#define DPE_DATA_MAX 512
#define DPE_MAGIC    0x44504543 // "DPEC"

struct dpe_cmd_hdr {
    uint32_t magic;
    uint32_t cmd_id;
    uint32_t profile;
};

struct dpe_resp_hdr {
    uint32_t magic;
    uint32_t status;
    uint32_t profile;
};


#define DPE_HANDLE_SIZE 16
#define DPE_CERT_SIZE   2048

#ifndef DPE_PROFILE
#define DPE_PROFILE DPE_PROFILE_384
#endif

#if (DPE_PROFILE == DPE_PROFILE_256)
#define DPE_ECC_SIZE 32
#endif

#if (DPE_PROFILE == DPE_PROFILE_384)
#define DPE_ECC_SIZE 48
#endif

struct dpe_get_profile_response {
    struct dpe_resp_hdr resp_hdr;
    uint16_t major_version;
    uint16_t minor_version;
    uint32_t vendor_id;
    uint32_t vendor_sku;
    uint32_t max_tci_nodes;
    uint32_t flags;
};

struct dpe_new_handle_response {
    struct dpe_resp_hdr resp_hdr;
    uint8_t             handle[DPE_HANDLE_SIZE];
};

struct dpe_derive_child_response {
    struct dpe_resp_hdr resp_hdr;
    uint8_t             handle[DPE_HANDLE_SIZE];
    uint8_t             parent_handle[DPE_HANDLE_SIZE];
};

struct dpe_certify_key_response {
    struct dpe_resp_hdr resp_hdr;
    uint8_t             new_context_handle[DPE_HANDLE_SIZE];
    uint8_t             derived_pubkey_x[DPE_ECC_SIZE];
    uint8_t             derived_pubkey_y[DPE_ECC_SIZE];
    uint32_t            cert_size;
    uint8_t             cert[DPE_CERT_SIZE];
};

struct dpe_sign_response {
    struct dpe_resp_hdr resp_hdr;
    uint8_t             new_context_handle[DPE_HANDLE_SIZE];
    uint8_t             sig_r_or_hmac[DPE_ECC_SIZE];
    uint8_t             sig_s[DPE_ECC_SIZE];
};

struct dpe_get_tagged_tci_response {
    struct dpe_resp_hdr resp_hdr;
    uint8_t             tci_cumulative[DPE_ECC_SIZE];
    uint8_t             tci_current[DPE_ECC_SIZE];
};

struct dpe_get_certificate_chain_response {
    struct dpe_resp_hdr resp_hdr;
    uint32_t            certificate_size;
    uint8_t             certificate_chain[DPE_CERT_SIZE];
};

struct caliptra_invoke_dpe_req {
    caliptra_checksum checksum;
    uint32_t          data_size;
    uint8_t           data[DPE_DATA_MAX];
};

struct caliptra_invoke_dpe_resp {
    struct caliptra_resp_header cpl;
    uint32_t                    data_size;
    union {
        struct dpe_get_profile_response           get_profile;
        struct dpe_new_handle_response            new_handle;
        struct dpe_derive_child_response          derive_child;
        struct dpe_certify_key_response           certify_key;
        struct dpe_sign_response                  sign;
        struct dpe_get_tagged_tci_response        get_tagged_tci;
        struct dpe_get_certificate_chain_response get_certified_chain;
        uint8_t                                   data[sizeof(struct dpe_certify_key_response)];
    };
};

