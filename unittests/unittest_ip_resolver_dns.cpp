/*
Copyright (c) 2018 Contributors as noted in the AUTHORS file

This file is part of 0MQ.

0MQ is free software; you can redistribute it and/or modify it under
the terms of the GNU Lesser General Public License as published by
the Free Software Foundation; either version 3 of the License, or
(at your option) any later version.

0MQ is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <unity.h>
#include "../tests/testutil.hpp"

#include <ip_resolver.hpp>

extern "C" {
    struct dns_lut_t
    {
        const char *hostname;
        const char *ipv4;
        const char *ipv6;
    };

    static const struct dns_lut_t dns_lut[] = {
        { "ip.zeromq.org",       "10.100.0.1", "fdf5:d058:d656::1" },
        { "ipv4only.zeromq.org", "10.100.0.2", "::ffff:10.100.0.2" },
        { "ipv6only.zeromq.org", NULL,         "fdf5:d058:d656::2" },
    };

    //  Dummy getaddrinfo implementation to avoid making DNS queries in tests
    int getaddrinfo (const char *node_, const char *service_,
                     const struct addrinfo *hints_,
                     struct addrinfo **res_)
    {
        struct addrinfo ai;

        assert (service_ == NULL);

        if (hints_->ai_family != AF_INET && hints_->ai_family != AF_INET6) {
            return EAI_ADDRFAMILY;
        }

        bool ipv6 = (hints_->ai_family == AF_INET6);

        ai = *hints_;

        bool no_dns = hints_->ai_flags & AI_NUMERICHOST;

        unsigned lut_len = sizeof (dns_lut) / sizeof (dns_lut[0]);

        const char *ip = NULL;

        if (!no_dns) {
            for (unsigned i = 0; i < lut_len; i++) {
                if (strcmp (dns_lut[i].hostname, node_) == 0) {
                    if (ipv6) {
                        ip = dns_lut[i].ipv6;
                    } else {
                        ip = dns_lut[i].ipv4;

                        if (ip == NULL) {
                            //  No address associated with NAME
                            return EAI_NODATA;
                        }
                    }
                }
            }
        }

        if (ip == NULL) {
            //  No entry for 'node_' found in the LUT (or DNS is
            //  forbidden), assume that it's a numeric IP address
            ip = node_;
        }

        zmq::ip_addr_t addr;

        addr.generic.sa_family = ai.ai_family;

        int rc = 0;

        if (ai.ai_family == AF_INET) {
            ai.ai_addrlen = sizeof (struct sockaddr_in);
            rc = test_inet_pton (AF_INET, ip, &addr.ipv4.sin_addr);
        } else {
            ai.ai_addrlen = sizeof (struct sockaddr_in6);
            rc = test_inet_pton (AF_INET6, ip, &addr.ipv6.sin6_addr);
        }

        if (rc == 0) {
            //  NAME or SERVICE is unknown
            return EAI_NONAME;
        }

        ai.ai_addr = (struct sockaddr *)calloc (1, ai.ai_addrlen);
        if (ai.ai_addr == NULL) {
            return EAI_MEMORY;
        }

        memcpy (ai.ai_addr, &addr, ai.ai_addrlen);

        *res_ = (struct addrinfo *)calloc (1, sizeof (**res_));
        if (*res_ == NULL) {
            free (ai.ai_addr);
            return EAI_MEMORY;
        }

        **res_ = ai;

        return 0;
    }

#ifndef __THROW
# define __THROW
#endif

    void freeaddrinfo (struct addrinfo *res_) __THROW
    {
        if (res_->ai_addr) {
            free (res_->ai_addr);
            res_->ai_addr = NULL;
        }

        free (res_);
    }
}

//  Generate an invalid but well-defined 'ip_addr_t'. Avoids testing
//  uninitialized values if the code is buggy.
static zmq::ip_addr_t test_bad_addr (void)
{
    zmq::ip_addr_t addr;

    memset (&addr, 0xba, sizeof (addr));

    return addr;
}

static void validate_ipv4_addr (const zmq::ip_addr_t &addr_,
                                const struct in_addr &expected_addr_,
                                uint16_t expected_port_ = 0)
{
    const sockaddr_in *ip4_addr = &addr_.ipv4;

    TEST_ASSERT_EQUAL (AF_INET, addr_.generic.sa_family);
    TEST_ASSERT_EQUAL (expected_addr_.s_addr, ip4_addr->sin_addr.s_addr);
    TEST_ASSERT_EQUAL (htons (expected_port_), ip4_addr->sin_port);
}

static void validate_ipv6_addr (const zmq::ip_addr_t &addr_,
                                const struct in6_addr &expected_addr_,
                                uint16_t expected_port_ = 0,
                                uint16_t expected_zone_ = 0)
{
    const sockaddr_in6 *ip6_addr = &addr_.ipv6;

    TEST_ASSERT_EQUAL (AF_INET6, addr_.generic.sa_family);

    int neq = memcmp (&ip6_addr->sin6_addr,
                      &expected_addr_,
                      sizeof (expected_addr_));

    TEST_ASSERT_EQUAL (0, neq);
    TEST_ASSERT_EQUAL (htons (expected_port_), ip6_addr->sin6_port);
    TEST_ASSERT_EQUAL (expected_zone_, ip6_addr->sin6_scope_id);
}

void test_dns_ipv4_simple ()
{
    zmq::ip_resolver_options_t resolver_opts;
    zmq::ip_addr_t addr;
    struct in_addr expected_addr1, expected_addr2;

    resolver_opts
        .bindable (false)
        .allow_dns (true)
        .allow_nic_name (false)
        .expect_port (false)
        .ipv6 (false);

    zmq::ip_resolver_t resolver (resolver_opts);

    assert (test_inet_pton (AF_INET, "10.100.0.1", &expected_addr1) == 1);
    assert (test_inet_pton (AF_INET, "10.100.0.2", &expected_addr2) == 1);

    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (0, resolver.resolve(&addr, "ip.zeromq.org"));
    validate_ipv4_addr (addr, expected_addr1);

    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (0, resolver.resolve(&addr, "ipv4only.zeromq.org"));
    validate_ipv4_addr (addr, expected_addr2);

    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (0, resolver.resolve(&addr, "[ip.zeromq.org]"));
    validate_ipv4_addr (addr, expected_addr1);

    TEST_ASSERT_EQUAL (-1, resolver.resolve(&addr, "ipv6only.zeromq.org"));

    TEST_ASSERT_EQUAL (-1, resolver.resolve(&addr, "invalid.zeromq.org"));

    //  Numeric IPs should still work
    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (0, resolver.resolve(&addr, "10.100.0.1"));
    validate_ipv4_addr (addr, expected_addr1);

    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (0, resolver.resolve(&addr, "10.100.0.2"));
    validate_ipv4_addr (addr, expected_addr2);
}

void test_dns_ipv4_port ()
{
    zmq::ip_resolver_options_t resolver_opts;
    zmq::ip_addr_t addr;
    struct in_addr expected_addr1, expected_addr2;

    resolver_opts
        .bindable (false)
        .allow_dns (true)
        .allow_nic_name (false)
        .expect_port (true)
        .ipv6 (false);

    zmq::ip_resolver_t resolver (resolver_opts);

    assert (test_inet_pton (AF_INET, "10.100.0.1", &expected_addr1) == 1);
    assert (test_inet_pton (AF_INET, "10.100.0.2", &expected_addr2) == 1);

    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (0, resolver.resolve(&addr, "ip.zeromq.org:1234"));
    validate_ipv4_addr (addr, expected_addr1, 1234);

    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (0, resolver.resolve(&addr, "ipv4only.zeromq.org:1234"));
    validate_ipv4_addr (addr, expected_addr2, 1234);

    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (0, resolver.resolve(&addr, "[ip.zeromq.org]:1234"));
    validate_ipv4_addr (addr, expected_addr1, 1234);

    //  Numeric IPs should still work
    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (0, resolver.resolve(&addr, "10.100.0.1:123"));
    validate_ipv4_addr (addr, expected_addr1, 123);

    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (0, resolver.resolve(&addr, "10.100.0.2:456"));
    validate_ipv4_addr (addr, expected_addr2, 456);
}

void test_dns_ipv4_deny ()
{
    zmq::ip_resolver_options_t resolver_opts;
    zmq::ip_addr_t addr;

    resolver_opts
        .bindable (false)
        .allow_dns (false)
        .allow_nic_name (false)
        .expect_port (false)
        .ipv6 (false);

    zmq::ip_resolver_t resolver (resolver_opts);

    //  DNS resolution shouldn't work when disallowed
    TEST_ASSERT_EQUAL (-1, resolver.resolve(&addr, "ip.zeromq.org"));
    TEST_ASSERT_EQUAL (-1, resolver.resolve(&addr, "ipv4only.zeromq.org"));
}

void test_dns_ipv6_deny ()
{
    zmq::ip_resolver_options_t resolver_opts;
    zmq::ip_addr_t addr;

    resolver_opts
        .bindable (false)
        .allow_dns (false)
        .allow_nic_name (false)
        .expect_port (false)
        .ipv6 (true);

    zmq::ip_resolver_t resolver (resolver_opts);

    //  DNS resolution shouldn't work when disallowed
    TEST_ASSERT_EQUAL (-1, resolver.resolve(&addr, "ip.zeromq.org"));
    TEST_ASSERT_EQUAL (-1, resolver.resolve(&addr, "ipv6only.zeromq.org"));
}

void test_dns_ipv6_simple ()
{
    zmq::ip_resolver_options_t resolver_opts;
    zmq::ip_addr_t addr;
    struct in6_addr expected_addr1, expected_addr2, expected_addr_v4;

    resolver_opts
        .bindable (false)
        .allow_dns (true)
        .allow_nic_name (false)
        .expect_port (false)
        .ipv6 (true);

    zmq::ip_resolver_t resolver (resolver_opts);

    assert (test_inet_pton (AF_INET6, "fdf5:d058:d656::1",
                            &expected_addr1) == 1);
    assert (test_inet_pton (AF_INET6, "fdf5:d058:d656::2",
                            &expected_addr2) == 1);
    assert (test_inet_pton (AF_INET6, "::ffff:10.100.0.2",
                            &expected_addr_v4) == 1);

    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (0, resolver.resolve(&addr, "ip.zeromq.org"));
    validate_ipv6_addr (addr, expected_addr1);

    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (0, resolver.resolve(&addr, "ipv6only.zeromq.org"));
    validate_ipv6_addr (addr, expected_addr2);

    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (0, resolver.resolve(&addr, "[ip.zeromq.org]"));
    validate_ipv6_addr (addr, expected_addr1);
}

void test_dns_ipv6_scope ()
{
    zmq::ip_resolver_options_t resolver_opts;
    zmq::ip_addr_t addr;
    struct in6_addr expected_addr1, expected_addr2, expected_addr_v4;

    resolver_opts
        .bindable (false)
        .allow_dns (true)
        .allow_nic_name (false)
        .expect_port (false)
        .ipv6 (true);

    zmq::ip_resolver_t resolver (resolver_opts);

    assert (test_inet_pton (AF_INET6, "fdf5:d058:d656::1",
                            &expected_addr1) == 1);
    assert (test_inet_pton (AF_INET6, "fdf5:d058:d656::2",
                            &expected_addr2) == 1);
    assert (test_inet_pton (AF_INET6, "::ffff:10.100.0.2",
                            &expected_addr_v4) == 1);

    //  Not sure if that's very useful but you could technically add a scope
    //  identifier to a hostname
    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (0, resolver.resolve(&addr, "ip.zeromq.org%4"));
    validate_ipv6_addr (addr, expected_addr1, 0, 4);

    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (0, resolver.resolve(&addr, "[ip.zeromq.org%5]"));
    validate_ipv6_addr (addr, expected_addr1, 0, 5);

    //  Numeric IPs should still work
    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (0, resolver.resolve(&addr, "fdf5:d058:d656::1"));
    validate_ipv6_addr (addr, expected_addr1);

    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (0, resolver.resolve(&addr, "fdf5:d058:d656::2"));
    validate_ipv6_addr (addr, expected_addr2);
}

void test_dns_ipv6_port ()
{
    zmq::ip_resolver_options_t resolver_opts;
    zmq::ip_addr_t addr;
    struct in6_addr expected_addr1, expected_addr2, expected_addr_v4;

    resolver_opts
        .bindable (false)
        .allow_dns (true)
        .allow_nic_name (false)
        .expect_port (true)
        .ipv6 (true);

    zmq::ip_resolver_t resolver (resolver_opts);

    assert (test_inet_pton (AF_INET6, "fdf5:d058:d656::1",
                            &expected_addr1) == 1);
    assert (test_inet_pton (AF_INET6, "fdf5:d058:d656::2",
                            &expected_addr2) == 1);
    assert (test_inet_pton (AF_INET6, "::ffff:10.100.0.2",
                            &expected_addr_v4) == 1);

    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (0, resolver.resolve(&addr, "ip.zeromq.org:1234"));
    validate_ipv6_addr (addr, expected_addr1, 1234);

    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (0, resolver.resolve(&addr, "ipv6only.zeromq.org:1234"));
    validate_ipv6_addr (addr, expected_addr2, 1234);

    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (0, resolver.resolve(&addr, "[ip.zeromq.org]:1234"));
    validate_ipv6_addr (addr, expected_addr1, 1234);

    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (0, resolver.resolve(&addr, "ip.zeromq.org%8:1234"));
    validate_ipv6_addr (addr, expected_addr1, 1234, 8);

    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (0, resolver.resolve(&addr, "[ip.zeromq.org%9]:5678"));
    validate_ipv6_addr (addr, expected_addr1, 5678, 9);
}

void test_dns_ipv4_in_ipv6_simple ()
{
    zmq::ip_resolver_options_t resolver_opts;
    zmq::ip_addr_t addr;
    struct in6_addr expected_addr_v4;

    resolver_opts
        .bindable (false)
        .allow_dns (true)
        .allow_nic_name (false)
        .expect_port (false)
        .ipv6 (true);

    zmq::ip_resolver_t resolver (resolver_opts);

    assert (test_inet_pton (AF_INET6, "::ffff:10.100.0.2",
                            &expected_addr_v4) == 1);
    //  If a host doesn't have an IPv6 then it should resolve as an embedded v4
    //  address in an IPv6
    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (0, resolver.resolve(&addr, "ipv4only.zeromq.org"));
    validate_ipv6_addr (addr, expected_addr_v4);

    TEST_ASSERT_EQUAL (-1, resolver.resolve(&addr, "invalid.zeromq.org"));
}

void test_dns_ipv4_in_ipv6_port ()
{
    zmq::ip_resolver_options_t resolver_opts;
    zmq::ip_addr_t addr;
    struct in6_addr expected_addr1, expected_addr2, expected_addr_v4;

    resolver_opts
        .bindable (false)
        .allow_dns (true)
        .allow_nic_name (false)
        .expect_port (true)
        .ipv6 (true);

    zmq::ip_resolver_t resolver (resolver_opts);

    assert (test_inet_pton (AF_INET6, "fdf5:d058:d656::1",
                            &expected_addr1) == 1);
    assert (test_inet_pton (AF_INET6, "fdf5:d058:d656::2",
                            &expected_addr2) == 1);
    assert (test_inet_pton (AF_INET6, "::ffff:10.100.0.2",
                            &expected_addr_v4) == 1);

    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (0, resolver.resolve(&addr, "ip.zeromq.org:1234"));
    validate_ipv6_addr (addr, expected_addr1, 1234);

    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (0, resolver.resolve(&addr, "ipv6only.zeromq.org:1234"));
    validate_ipv6_addr (addr, expected_addr2, 1234);

    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (0, resolver.resolve(&addr, "[ip.zeromq.org]:1234"));
    validate_ipv6_addr (addr, expected_addr1, 1234);

    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (0, resolver.resolve(&addr, "ip.zeromq.org%8:1234"));
    validate_ipv6_addr (addr, expected_addr1, 1234, 8);

    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (0, resolver.resolve(&addr, "[ip.zeromq.org%9]:5678"));
    validate_ipv6_addr (addr, expected_addr1, 5678, 9);
}

int main (void)
{
    setup_test_environment ();

    UNITY_BEGIN ();

    RUN_TEST (test_dns_ipv4_simple);
    RUN_TEST (test_dns_ipv4_port);
    RUN_TEST (test_dns_ipv4_deny);

    if (is_ipv6_available ()) {
        RUN_TEST (test_dns_ipv6_deny);
        RUN_TEST (test_dns_ipv6_simple);
        RUN_TEST (test_dns_ipv6_scope);
        RUN_TEST (test_dns_ipv6_port);
        RUN_TEST (test_dns_ipv4_in_ipv6_simple);
        RUN_TEST (test_dns_ipv4_in_ipv6_port);
    }

    return UNITY_END ();
}
