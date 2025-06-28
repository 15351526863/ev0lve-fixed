#pragma once
#include <array>
#include <cstddef>
#include <string>
#include <cstring>

// Compile-time string encryption using XOR
namespace xor_detail {
    // Generate compile-time random key based on file and line
    constexpr auto seed = __TIME__[7] - '0' + __TIME__[6] * 10 - '0' * 10
        + __TIME__[4] * 60 - '0' * 60 + __TIME__[3] * 600 - '0' * 600
        + __TIME__[1] * 3600 - '0' * 3600 + __TIME__[0] * 36000 - '0' * 36000;

    template<int N>
    struct key_generator {
        constexpr key_generator() : value{} {
            auto s = seed + N;
            for (auto& c : value) {
                c = static_cast<char>((s = s * 1103515245 + 12345) & 0xFF);
            }
        }
        char value[N];
    };

    // XOR encrypted string holder
    template<typename CharT, size_t N>
    class xor_string {
    private:
        std::array<CharT, N> encrypted;
        std::array<char, N> key;
        mutable CharT decrypted_buffer[N];
        mutable bool is_decrypted = false;

        constexpr CharT encrypt_char(CharT c, size_t i) const {
            return static_cast<CharT>(c ^ static_cast<CharT>(key[i % key.size()]));
        }

        void ensure_decrypted() const {
            if (!is_decrypted) {
                for (size_t i = 0; i < N; ++i) {
                    decrypted_buffer[i] = encrypt_char(encrypted[i], i);
                }
                is_decrypted = true;
            }
        }

    public:
        template<size_t... Is>
        constexpr xor_string(const CharT(&str)[N], std::index_sequence<Is...>)
            : encrypted{ encrypt_char(str[Is], Is)... }, key{ key_generator<N>{}.value }, decrypted_buffer{} {
        }

        // Copy constructor
        xor_string(const xor_string& other)
            : encrypted(other.encrypted), key(other.key), decrypted_buffer{}, is_decrypted(false) {
        }

        // Get decrypted C-style string - main method used in anti_debugger.cpp
        const CharT* crypt_get() const {
            ensure_decrypted();
            return decrypted_buffer;
        }

        // Implicit conversion to string type
        operator std::basic_string<CharT>() const {
            ensure_decrypted();
            return std::basic_string<CharT>(decrypted_buffer, N - 1);
        }

        // Get C-style string (alternative method)
        const CharT* c_str() const {
            return crypt_get();
        }

        // Get as std::string/std::wstring
        std::basic_string<CharT> str() const {
            ensure_decrypted();
            return std::basic_string<CharT>(decrypted_buffer, N - 1);
        }
    };

    // Factory function for creating xor_string
    template<typename CharT, size_t N>
    constexpr auto make_xor_string(const CharT(&str)[N]) {
        return xor_string<CharT, N>(str, std::make_index_sequence<N>{});
    }
}

// Main macro that handles both char and wchar_t strings
#define xor(str) (xor_detail::make_xor_string(str))