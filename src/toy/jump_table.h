#ifndef RVC_RUN

#    include "common.h"

#    include <cstdint>
#    include <unordered_map>

extern void *jump_table[];
extern std::unordered_map<uint64_t, void *> jump_table_hash;

static void dummy() {
#endif

    //=========================================================================================================
    // Start jump table
    //=========================================================================================================

#define JUMP_CACHE_SIZE 5

    static uint64_t last_jump_ip = 0;
    static void *last_jump_address = nullptr;

    static uint64_t jump_index_cache[JUMP_CACHE_SIZE] = {};
    static void *jump_address_cache[JUMP_CACHE_SIZE] = {};
    static int cur_cache_index = 0;

    auto indirect_jump = [&](uint64_t ip) {
        // Top cache hit
        if (last_jump_ip == ip) {
            return;
        }

        // Recall targets
        for (int i = 0; i < JUMP_CACHE_SIZE; ++i) {
            int idx = (cur_cache_index + JUMP_CACHE_SIZE - 1 - i) % JUMP_CACHE_SIZE;

            // Not cached yet
            if (!jump_address_cache[idx]) {
                break;
            }

            // Sub cache hit
            if (jump_index_cache[idx] == ip) {
                // Move cache index to next
                cur_cache_index = (idx + 1) % JUMP_CACHE_SIZE;

                // Update top cache
                last_jump_ip = ip;
                last_jump_address = jump_address_cache[idx];
                return;
            }
        }

        auto it = jump_table_hash.find(ip);
        if (it == jump_table_hash.end())
            error("Invalid branch address!!!");

        // Update top cache
        last_jump_ip = ip;
        last_jump_address = it->second;

        // Update sub cache
        jump_index_cache[cur_cache_index] = ip;
        jump_address_cache[cur_cache_index] = last_jump_address;

        // Move cache index to next
        cur_cache_index = (cur_cache_index + 1) % JUMP_CACHE_SIZE;
    };

#define INDIRECT_JUMP(ip)                                                                                              \
    indirect_jump(ip);                                                                                                 \
    goto *last_jump_address;

    //=========================================================================================================
    // End jump table
    //=========================================================================================================

#ifndef RVC_RUN
}
#endif