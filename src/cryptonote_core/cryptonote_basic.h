// Copyright (c) 2012-2013 The Cryptonote developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#pragma once

#include <boost/variant.hpp>
#include <boost/functional/hash/hash.hpp>
#include <iostream>
#include <vector>
#include <cstring>  // memcmp
#include <sstream>
#include "serialization/serialization.h"
#include "serialization/variant.h"
#include "serialization/vector.h"
#include "serialization/binary_archive.h"
#include "serialization/json_archive.h"
#include "serialization/debug_archive.h"
#include "serialization/crypto.h"
#include "serialization/pricing_record.h"
#include "serialization/keyvalue_serialization.h" // eepe named serialization
#include "string_tools.h"
#include "cryptonote_config.h"
#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "misc_language.h"
#include "tx_extra.h"
#include "ringct/rctTypes.h"
#include "cryptonote_protocol/blobdatatype.h"
#include "offshore/pricing_record.h"


namespace cryptonote
{
  struct block;
  class transaction;
  class transaction_prefix;
  struct tx_extra_merge_mining_tag;

  // Implemented in cryptonote_format_utils.cpp
  bool get_transaction_hash(const transaction& t, crypto::hash& res);
  void get_transaction_prefix_hash(const transaction_prefix& tx, crypto::hash& h);
  void get_blob_hash(const blobdata& blob, crypto::hash& res);
  bool get_mm_tag_from_extra(const std::vector<uint8_t>& tx, tx_extra_merge_mining_tag& mm_tag);

  const static crypto::hash null_hash = AUTO_VAL_INIT(null_hash);
  const static crypto::public_key null_pkey = AUTO_VAL_INIT(null_pkey);

  typedef std::vector<crypto::signature> ring_signature;


  /* outputs */

  struct txout_to_script
  {
    std::vector<crypto::public_key> keys;
    std::vector<uint8_t> script;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(keys)
      FIELD(script)
    END_SERIALIZE()
  };

  struct txout_to_scripthash
  {
    crypto::hash hash;
  };

  struct txout_to_key
  {
    txout_to_key() { }
    txout_to_key(const crypto::public_key &_key) : key(_key) { }
    crypto::public_key key;
  };

  struct txout_offshore
  {
    txout_offshore() { }
    txout_offshore(const crypto::public_key &_key) : key(_key) { }
    crypto::public_key key;
  };

  struct txout_xasset
  {
    txout_xasset() { }
    txout_xasset(const crypto::public_key &_key, const std::string &_asset_type) : key(_key), asset_type(_asset_type) { }
    crypto::public_key key;
    std::string asset_type;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(key)
      FIELD(asset_type)
    END_SERIALIZE()
  };

  /* inputs */

  struct txin_gen
  {
    size_t height;

    BEGIN_SERIALIZE_OBJECT()
      VARINT_FIELD(height)
    END_SERIALIZE()
  };

  struct txin_to_script
  {
    crypto::hash prev;
    size_t prevout;
    std::vector<uint8_t> sigset;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(prev)
      VARINT_FIELD(prevout)
      FIELD(sigset)
    END_SERIALIZE()
  };

  struct txin_to_scripthash
  {
    crypto::hash prev;
    size_t prevout;
    txout_to_script script;
    std::vector<uint8_t> sigset;

    BEGIN_SERIALIZE_OBJECT()
      FIELD(prev)
      VARINT_FIELD(prevout)
      FIELD(script)
      FIELD(sigset)
    END_SERIALIZE()
  };

  struct txin_to_key
  {
    uint64_t amount;
    std::vector<uint64_t> key_offsets;
    crypto::key_image k_image;      // double spending protection

    BEGIN_SERIALIZE_OBJECT()
      VARINT_FIELD(amount)
      FIELD(key_offsets)
      FIELD(k_image)
    END_SERIALIZE()
  };

  struct txin_offshore
  {
    uint64_t amount;
    std::vector<uint64_t> key_offsets;
    crypto::key_image k_image;

    BEGIN_SERIALIZE_OBJECT()
    VARINT_FIELD(amount)
    FIELD(key_offsets)
    FIELD(k_image)
    END_SERIALIZE()
  };

  struct txin_onshore
  {
    uint64_t amount;
    std::vector<uint64_t> key_offsets;
    crypto::key_image k_image;
    
    BEGIN_SERIALIZE_OBJECT()
    VARINT_FIELD(amount)
    FIELD(key_offsets)
    FIELD(k_image)
    END_SERIALIZE()
  };

  struct txin_xasset
  {
    uint64_t amount;
    std::string asset_type;
    std::vector<uint64_t> key_offsets;
    crypto::key_image k_image;      // double spending protection

    BEGIN_SERIALIZE_OBJECT()
    VARINT_FIELD(amount)
    FIELD(asset_type)
    FIELD(key_offsets)
    FIELD(k_image)
    END_SERIALIZE()
  };
  
  typedef boost::variant<txin_gen, txin_to_script, txin_to_scripthash, txin_to_key, txin_offshore, txin_onshore, txin_xasset> txin_v;

  typedef boost::variant<txout_to_script, txout_to_scripthash, txout_to_key, txout_offshore, txout_xasset> txout_target_v;

  //typedef std::pair<uint64_t, txout> out_t;
  struct tx_out
  {
    uint64_t amount;
    txout_target_v target;

    BEGIN_SERIALIZE_OBJECT()
      VARINT_FIELD(amount)
      FIELD(target)
    END_SERIALIZE()
  };

  enum loki_version
  {
    loki_version_0 = 0,
    loki_version_1,
    loki_version_2,
    loki_version_3_per_output_unlock_times,
    loki_version_4_tx_types,
  };

  class transaction_prefix
  {

  public:
    enum BLOB_TYPE blob_type;
    // tx information
    size_t   version;
    uint64_t unlock_time;  //number of block (or time), used as a limitation like: spend this tx not early then block/time

    std::vector<txin_v> vin;
    std::vector<tx_out> vout;
    //extra
    std::vector<uint8_t> extra;
    // Block height to use PR from
    uint64_t pricing_record_height;
    // Circulating supply information
    std::vector<uint8_t> offshore_data;
    uint64_t amount_burnt;
    uint64_t amount_minted;

    //
    // NOTE: Loki specific
    //
    std::vector<uint64_t> output_unlock_times;
    enum loki_type_t
    {
      loki_type_standard,
      loki_type_deregister,
      loki_type_key_image_unlock,
      loki_type_count,
    };

    union
    {
      bool is_deregister;
      uint16_t type;
    };

    BEGIN_SERIALIZE()
      VARINT_FIELD(version)
      if (version > loki_version_2 && (blob_type == BLOB_TYPE_CRYPTONOTE_LOKI || blob_type == BLOB_TYPE_CRYPTONOTE_XTNC))
      {
        FIELD(output_unlock_times)
        if (version == loki_version_3_per_output_unlock_times)
          FIELD(is_deregister)
      }
      VARINT_FIELD(unlock_time)
      FIELD(vin)
      FIELD(vout)
      if (blob_type == BLOB_TYPE_CRYPTONOTE_LOKI || blob_type == BLOB_TYPE_CRYPTONOTE_XTNC)
      {
        if (version >= loki_version_3_per_output_unlock_times && vout.size() != output_unlock_times.size()) return false;
      }
      FIELD(extra)
      if ((blob_type == BLOB_TYPE_CRYPTONOTE_LOKI || blob_type == BLOB_TYPE_CRYPTONOTE_XTNC) && version >= loki_version_4_tx_types)
      {
        VARINT_FIELD(type)
        if (static_cast<uint16_t>(type) >= loki_type_count) return false;
      }
      if (blob_type == BLOB_TYPE_CRYPTONOTE_XHV && version >= OFFSHORE_TRANSACTION_VERSION) {
        VARINT_FIELD(pricing_record_height)
        if (version < 5)
          FIELD(offshore_data)
        VARINT_FIELD(amount_burnt)
        VARINT_FIELD(amount_minted)
      }
    END_SERIALIZE()


  protected:
    transaction_prefix() : blob_type(BLOB_TYPE_CRYPTONOTE) {}
  };

  class transaction: public transaction_prefix
  {
  public:
    std::vector<std::vector<crypto::signature> > signatures; //count signatures  always the same as inputs count
    rct::rctSig rct_signatures;

    transaction();
    virtual ~transaction();
    void set_null();

    BEGIN_SERIALIZE_OBJECT()
      FIELDS(*static_cast<transaction_prefix *>(this))

      if (version == 1 && blob_type != BLOB_TYPE_CRYPTONOTE2 && blob_type != BLOB_TYPE_CRYPTONOTE3)
      {
        ar.tag("signatures");
        ar.begin_array();
        PREPARE_CUSTOM_VECTOR_SERIALIZATION(vin.size(), signatures);
        bool signatures_not_expected = signatures.empty();
        if (!signatures_not_expected && vin.size() != signatures.size())
          return false;

        for (size_t i = 0; i < vin.size(); ++i)
        {
          size_t signature_size = get_signature_size(vin[i]);
          if (signatures_not_expected)
          {
            if (0 == signature_size)
              continue;
            else
              return false;
          }

          PREPARE_CUSTOM_VECTOR_SERIALIZATION(signature_size, signatures[i]);
          if (signature_size != signatures[i].size())
            return false;

          FIELDS(signatures[i]);

          if (vin.size() - i > 1)
            ar.delimit_array();
        }
        ar.end_array();
      }
      else
      {
        ar.tag("rct_signatures");
        if (!vin.empty())
        {
          ar.begin_obj