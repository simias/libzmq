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

class test_ip_resolver_t : public zmq::ip_resolver_t
{
public:
    test_ip_resolver_t (zmq::ip_resolver_options_t opts_) :
        ip_resolver_t (opts_)
    {
    }

protected:
    struct dns_lut_t
    {
        const char *hostname;
        const char *ipv4;
        const char *ipv6;
    };

    virtual int do_getaddrinfo (const char *node_, const char *service_,
                                const struct addrinfo *hints_,
                                struct addrinfo **res_)
    {
        static const struct dns_lut_t dns_lut[] = {
            { "ip.zeromq.org",       "10.100.0.1", "fdf5:d058:d656::1" },
            { "ipv4only.zeromq.org", "10.100.0.2", "::ffff:10.100.0.2" },
            { "ipv6only.zeromq.org", NULL,         "fdf5:d058:d656::2" },
        };
        unsigned lut_len = sizeof (dns_lut) / sizeof (dns_lut[0]);
        struct addrinfo ai;

        assert (service_ == NULL);

        bool ipv6 = (hints_->ai_family == AF_INET6);
        bool no_dns = hints_->ai_flags & AI_NUMERICHOST;
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

        //  Call the real getaddrinfo implementation, making sure that it won't
        //  attempt to resolve using DNS
        ai = *hints_;
        ai.ai_flags |= AI_NUMERICHOST;

        return zmq::ip_resolver_t::do_getaddrinfo (ip, NULL, &ai, res_);
    }

    virtual unsigned int do_if_nametoindex(const char *ifname_)
    {
        static const char * dummy_interfaces[] = {
            "lo0",
            "eth0",
            "eth1",
        };
        unsigned lut_len =
            sizeof (dummy_interfaces) / sizeof (dummy_interfaces[0]);

        for (unsigned i = 0; i < lut_len; i++) {
            if (strcmp (dummy_interfaces[i], ifname_) == 0) {
                //  The dummy index will be the position in the array + 1 (0 is
                //  invalid)
                return i + 1;
            }
        }

        //  Not found
        return 0;
    }
};

//  Attempt a resolution and test the results. If 'expected_addr_' is NULL
//  assume that the resolution is meant to fail.
static void test_resolve(zmq::ip_resolver_options_t opts_,
                         const char *name_,
                         const char *expected_addr_,
                         uint16_t expected_port_ = 0,
                         uint16_t expected_zone_ = 0)
{
    zmq::ip_addr_t addr;
    const int family = opts_.ipv6() ? AF_INET6 : AF_INET;

    if (family == AF_INET6 && !is_ipv6_available ()) {
        TEST_IGNORE_MESSAGE ("ipv6 is not available");
    }

    //  Generate an invalid but well-defined 'ip_addr_t'. Avoids testing
    //  uninitialized values if the code is buggy.
    memset (&addr, 0xba, sizeof (addr));

    test_ip_resolver_t resolver (opts_);

    int rc = resolver.resolve (&addr, name_);

    if (expected_addr_ == NULL) {
        TEST_ASSERT_EQUAL (-1, rc);
        return;
    } else {
        TEST_ASSERT_EQUAL (0, rc);
    }

    TEST_ASSERT_EQUAL (family, addr.generic.sa_family);

    if (family == AF_INET6) {
        struct in6_addr expected_addr;
        const sockaddr_in6 *ip6_addr = &addr.ipv6;

        assert (test_inet_pton (AF_INET6, expected_addr_, &expected_addr) == 1);

        int neq = memcmp (&ip6_addr->sin6_addr,
                          &expected_addr,
                          sizeof (expected_addr_));

        TEST_ASSERT_EQUAL (0, neq);
        TEST_ASSERT_EQUAL (htons (expected_port_), ip6_addr->sin6_port);
        TEST_ASSERT_EQUAL (expected_zone_, ip6_addr->sin6_scope_id);
    } else {
        struct in_addr expected_addr;
        const sockaddr_in *ip4_addr = &addr.ipv4;

        assert (test_inet_pton (AF_INET, expected_addr_, &expected_addr) == 1);

        TEST_ASSERT_EQUAL (AF_INET, addr.generic.sa_family);
        TEST_ASSERT_EQUAL (expected_addr.s_addr, ip4_addr->sin_addr.s_addr);
        TEST_ASSERT_EQUAL (htons (expected_port_), ip4_addr->sin_port);
    }
}

static zmq::ip_addr_t test_bad_addr (void)
{
    zmq::ip_addr_t addr;

    memset (&addr, 0xba, sizeof (addr));

    return addr;
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

static void validate_ipv4_addr (const zmq::ip_addr_t &addr_,
                                const struct in_addr &expected_addr_,
                                uint16_t expected_port_ = 0)
{
    const sockaddr_in *ip4_addr = &addr_.ipv4;

    TEST_ASSERT_EQUAL (AF_INET, addr_.generic.sa_family);
    TEST_ASSERT_EQUAL (expected_addr_.s_addr, ip4_addr->sin_addr.s_addr);
    TEST_ASSERT_EQUAL (htons (expected_port_), ip4_addr->sin_port);
}

// Helper macro to define the v4/v6 function pairs
#define MAKE_TEST_V4V6(_test)                   \
    static void _test ## _ipv4 ()               \
    {                                           \
        _test (false);                          \
    }                                           \
                                                \
    static void _test ## _ipv6 ()               \
    {                                           \
        _test (true);                           \
    }

static void test_bind_any (int ipv6_)
{
    zmq::ip_resolver_options_t resolver_opts;
    zmq::ip_addr_t addr;
    int rc;

    resolver_opts
        .bindable (true)
        .allow_dns (false)
        .allow_nic_name (false)
        .expect_port (true)
        .ipv6 (ipv6_);

    test_ip_resolver_t resolver (resolver_opts);

    addr = test_bad_addr ();
    rc = resolver.resolve(&addr, "*:*");

    TEST_ASSERT_EQUAL (0, rc);

    if (ipv6_) {
        struct in6_addr anyaddr;

#ifdef ZMQ_HAVE_VXWORKS
        anyaddr = IN6ADDR_ANY_INIT;
#else
        anyaddr = in6addr_any;
#endif
        validate_ipv6_addr (addr, anyaddr, 0);
    } else {
        struct in_addr anyaddr;

        anyaddr.s_addr = htonl (INADDR_ANY);

        validate_ipv4_addr (addr, anyaddr, 0);
    }
}
MAKE_TEST_V4V6 (test_bind_any)

static void test_nobind_any (int ipv6_)
{
    zmq::ip_resolver_options_t resolver_opts;

    resolver_opts
        .expect_port (true)
        .ipv6 (ipv6_);

    //  Wildcard should be rejected if we're not looking for a
    //  bindable address
    test_resolve (resolver_opts, "*:*", NULL);
}
MAKE_TEST_V4V6 (test_nobind_any)

static void test_nobind_any_port (int ipv6_)
{
    zmq::ip_resolver_options_t resolver_opts;

    resolver_opts
        .expect_port (true)
        .ipv6 (ipv6_);

    //  Wildcard should be rejected if we're not looking for a
    //  bindable address
    test_resolve (resolver_opts, "*:1234", NULL);
}
MAKE_TEST_V4V6 (test_nobind_any_port)

static void test_nobind_addr_anyport (int ipv6_)
{
    zmq::ip_resolver_options_t resolver_opts;

    resolver_opts
        .expect_port (true)
        .ipv6 (ipv6_);

    // This however works. Should it ? For the time being I'm going to
    // keep it that way for backcompat but I can't imagine why you'd
    // want a wildcard port if you're not binding.
    const char *expected = ipv6_ ? "::ffff:127.0.0.1" : "127.0.0.1";
    test_resolve (resolver_opts, "127.0.0.1:1234", expected, 1234);
}
MAKE_TEST_V4V6 (test_nobind_addr_anyport)

static void test_parse_ipv4_simple ()
{
    zmq::ip_resolver_options_t resolver_opts;

    test_resolve (resolver_opts, "1.2.128.129", "1.2.128.129");
}

static void test_parse_ipv4_zero ()
{
    zmq::ip_resolver_options_t resolver_opts;

    test_resolve (resolver_opts, "0.0.0.0", "0.0.0.0");
}

static void test_parse_ipv4_max ()
{
    zmq::ip_resolver_options_t resolver_opts;

    test_resolve (resolver_opts, "255.255.255.255", "255.255.255.255");
}

static void test_parse_ipv4_brackets ()
{
    zmq::ip_resolver_options_t resolver_opts;

    //  Not particularly useful, but valid
    test_resolve (resolver_opts, "[1.2.128.129]", "1.2.128.129");
}

static void test_parse_ipv4_brackets_missingl ()
{
    zmq::ip_resolver_options_t resolver_opts;

    test_resolve (resolver_opts, "1.2.128.129]", NULL);
}

static void test_parse_ipv4_brackets_missingr ()
{
    zmq::ip_resolver_options_t resolver_opts;

    test_resolve (resolver_opts, "[1.2.128.129", NULL);
}

static void test_parse_ipv4_brackets_bad ()
{
    zmq::ip_resolver_options_t resolver_opts;

    test_resolve (resolver_opts, "[1.2.128].129", NULL);
}

static void test_parse_ipv4_reject_port ()
{
    zmq::ip_resolver_options_t resolver_opts;

    //  No port expected, should be rejected
    test_resolve (resolver_opts, "1.2.128.129:123", NULL);
}

static void test_parse_ipv4_reject_any ()
{
    zmq::ip_resolver_options_t resolver_opts;

    //  No port expected, should be rejected
    test_resolve (resolver_opts, "1.2.128.129:*", NULL);
}

static void test_parse_ipv4_reject_ipv6 ()
{
    zmq::ip_resolver_options_t resolver_opts;

    //  No port expected, should be rejected
    test_resolve (resolver_opts, "::1", NULL);
}

static void test_parse_ipv4_port ()
{
    zmq::ip_resolver_options_t resolver_opts;

    resolver_opts.expect_port (true);

    test_resolve (resolver_opts, "1.2.128.129:123", "1.2.128.129", 123);
}

static void test_parse_ipv4_port0 ()
{
    zmq::ip_resolver_options_t resolver_opts;

    resolver_opts.expect_port (true);

    //  Port 0 is accepted and is equivalent to *
    test_resolve (resolver_opts, "1.2.128.129:0", "1.2.128.129", 0);
}

static void test_parse_ipv4_port_garbage ()
{
    zmq::ip_resolver_options_t resolver_opts;

    resolver_opts.expect_port (true);

    //  The code doesn't validate that the port doesn't contain garbage
    test_resolve (resolver_opts, "1.2.3.4:567bad", "1.2.3.4", 567);
}

static void test_parse_ipv4_port_missing ()
{
    zmq::ip_resolver_options_t resolver_opts;

    resolver_opts.expect_port (true);

    test_resolve (resolver_opts, "1.2.3.4", NULL);
}

static void test_parse_ipv4_port_bad ()
{
    zmq::ip_resolver_options_t resolver_opts;

    resolver_opts.expect_port (true);

    test_resolve (resolver_opts, "1.2.3.4:bad", NULL);
}

static void test_parse_ipv4_port_brackets ()
{
    zmq::ip_resolver_options_t resolver_opts;

    resolver_opts.expect_port (true);

    test_resolve (resolver_opts, "[192.168.1.1]:5555", "192.168.1.1", 5555);
}

static void test_parse_ipv4_port_brackets_bad ()
{
    zmq::ip_resolver_options_t resolver_opts;

    resolver_opts.expect_port (true);

    test_resolve (resolver_opts, "[192.168.1.1:]5555", NULL);
}

static void test_parse_ipv4_port_brackets_bad2 ()
{
    zmq::ip_resolver_options_t resolver_opts;

    resolver_opts.expect_port (true);

    test_resolve (resolver_opts, "[192.168.1.1:5555]", NULL);
}

static void test_parse_ipv4_wild_brackets_bad ()
{
    zmq::ip_resolver_options_t resolver_opts;

    resolver_opts.expect_port (true);

    test_resolve (resolver_opts, "[192.168.1.1:*]", NULL);
}

static void test_parse_ipv4_port_ipv6_reject ()
{
    zmq::ip_resolver_options_t resolver_opts;

    resolver_opts.expect_port (true);

    test_resolve (resolver_opts, "[::1]:1234", NULL);
}

static void test_parse_ipv6_simple ()
{
    zmq::ip_resolver_options_t resolver_opts;

    resolver_opts.ipv6 (true);

    test_resolve (resolver_opts, "::1", "::1");
}

static void test_parse_ipv6_simple2 ()
{
    zmq::ip_resolver_options_t resolver_opts;

    resolver_opts.ipv6 (true);

    test_resolve (resolver_opts, "abcd:1234::1:0:234", "abcd:1234::1:0:234");
}

static void test_parse_ipv6_zero ()
{
    zmq::ip_resolver_options_t resolver_opts;

    resolver_opts.ipv6 (true);

    test_resolve (resolver_opts, "::", "::");
}

static void test_parse_ipv6_max ()
{
    zmq::ip_resolver_options_t resolver_opts;

    resolver_opts.ipv6 (true);

    test_resolve (resolver_opts, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
                  "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
}

static void test_parse_ipv6_brackets ()
{
    zmq::ip_resolver_options_t resolver_opts;

    resolver_opts.ipv6 (true);

    test_resolve (resolver_opts, "[::1]", "::1");
}

static void test_parse_ipv6_brackets_missingl ()
{
    zmq::ip_resolver_options_t resolver_opts;

    resolver_opts.ipv6 (true);

    test_resolve (resolver_opts, "::1]", NULL);
}

static void test_parse_ipv6_brackets_missingr ()
{
    zmq::ip_resolver_options_t resolver_opts;

    resolver_opts.ipv6 (true);

    test_resolve (resolver_opts, "[::1", NULL);
}

static void test_parse_ipv6_brackets_bad ()
{
    zmq::ip_resolver_options_t resolver_opts;

    resolver_opts.ipv6 (true);

    test_resolve (resolver_opts, "[abcd:1234::1:]0:234", NULL);
}

static void test_parse_ipv6_port ()
{
    zmq::ip_resolver_options_t resolver_opts;

    resolver_opts
        .ipv6 (true)
        .expect_port (true);

    test_resolve (resolver_opts, "[1234::1]:80", "1234::1", 80);
}

static void test_parse_ipv6_port_any ()
{
    zmq::ip_resolver_options_t resolver_opts;

    resolver_opts
        .ipv6 (true)
        .expect_port (true);

    test_resolve (resolver_opts, "[1234::1]:*", "1234::1", 0);
}

static void test_parse_ipv6_port_nobrackets ()
{
    zmq::ip_resolver_options_t resolver_opts;

    resolver_opts
        .ipv6 (true)
        .expect_port (true);

    //  Should this be allowed? Seems error-prone but so far ZMQ accepts it.
    test_resolve (resolver_opts, "abcd:1234::1:0:234:123", "abcd:1234::1:0:234",
                  123);
}

static void test_parse_ipv4_in_ipv6 ()
{
    zmq::ip_resolver_options_t resolver_opts;

    resolver_opts
        .ipv6 (true);

    //  Parsing IPv4 should also work if an IPv6 is requested, it
    //  returns an IPv6 with the IPv4 address embedded
    test_resolve (resolver_opts, "11.22.33.44", "::ffff:11.22.33.44");
}

static void test_parse_ipv4_in_ipv6_port ()
{
    zmq::ip_resolver_options_t resolver_opts;

    resolver_opts
        .ipv6 (true)
        .expect_port (true);

    test_resolve (resolver_opts, "11.22.33.44:55", "::ffff:11.22.33.44", 55);
}

static void test_parse_ipv6_scope_int ()
{
    zmq::ip_resolver_options_t resolver_opts;

    resolver_opts
        .ipv6 (true);

    test_resolve (resolver_opts, "3000:4:5::1:234%2", "3000:4:5::1:234", 0, 2);
}

static void test_parse_ipv6_scope_zero ()
{
    zmq::ip_resolver_options_t resolver_opts;

    resolver_opts
        .ipv6 (true);

    test_resolve (resolver_opts, "3000:4:5::1:234%0", NULL);
}

static void test_parse_ipv6_scope_int_port ()
{
    zmq::ip_resolver_options_t resolver_opts;

    resolver_opts
        .expect_port (true)
        .ipv6 (true);

    test_resolve (resolver_opts, "3000:4:5::1:234%2:1111", "3000:4:5::1:234", 1111, 2);
}

static void test_parse_ipv6_scope_if ()
{
    zmq::ip_resolver_options_t resolver_opts;

    resolver_opts
        .ipv6 (true);

    test_resolve (resolver_opts, "3000:4:5::1:234%eth1", "3000:4:5::1:234", 0, 3);
}

static void test_parse_ipv6_scope_if_port ()
{
    zmq::ip_resolver_options_t resolver_opts;

    resolver_opts
        .expect_port (true)
        .ipv6 (true);

    test_resolve (resolver_opts, "3000:4:5::1:234%eth0:8080", "3000:4:5::1:234", 8080, 2);
}

static void test_parse_ipv6_scope_if_port_brackets ()
{
    zmq::ip_resolver_options_t resolver_opts;

    resolver_opts
        .expect_port (true)
        .ipv6 (true);

    test_resolve (resolver_opts, "[3000:4:5::1:234%eth0]:8080", "3000:4:5::1:234", 8080, 2);
}

static void test_parse_ipv6_scope_if_port_brackets_bad ()
{
    zmq::ip_resolver_options_t resolver_opts;

    resolver_opts
        .expect_port (true)
        .ipv6 (true);

    test_resolve (resolver_opts, "[3000:4:5::1:234]%eth0:8080", NULL);
}

static void test_parse_ipv6_scope_badif ()
{
    zmq::ip_resolver_options_t resolver_opts;

    resolver_opts
        .ipv6 (true);

    test_resolve (resolver_opts, "3000:4:5::1:234%bad0", NULL);
}

static void test_dns_ipv4_simple ()
{
    zmq::ip_resolver_options_t resolver_opts;

    resolver_opts
        .allow_dns (true);

    test_resolve (resolver_opts, "ip.zeromq.org", "10.100.0.1");
}

static void test_dns_ipv4_only ()
{
    zmq::ip_resolver_options_t resolver_opts;

    resolver_opts
        .allow_dns (true);

    test_resolve (resolver_opts, "ipv4only.zeromq.org", "10.100.0.2");
}

static void test_dns_ipv4_invalid ()
{
    zmq::ip_resolver_options_t resolver_opts;

    resolver_opts
        .allow_dns (true);

    test_resolve (resolver_opts, "invalid.zeromq.org", NULL);
}

static void test_dns_ipv4_ipv6 ()
{
    zmq::ip_resolver_options_t resolver_opts;

    resolver_opts
        .allow_dns (true);

    test_resolve (resolver_opts, "ipv6only.zeromq.org", NULL);
}

static void test_dns_ipv4_numeric ()
{
    zmq::ip_resolver_options_t resolver_opts;

    resolver_opts
        .allow_dns (true);

    //  Numeric IPs should still work
    test_resolve (resolver_opts, "5.4.3.2", "5.4.3.2");
}

static void test_dns_ipv4_port ()
{
    zmq::ip_resolver_options_t resolver_opts;

    resolver_opts
        .expect_port (true)
        .allow_dns (true);

    test_resolve (resolver_opts, "ip.zeromq.org:1234", "10.100.0.1", 1234);
}

static void test_dns_ipv6_simple ()
{
    zmq::ip_resolver_options_t resolver_opts;

    resolver_opts
        .ipv6 (true)
        .allow_dns (true);

    test_resolve (resolver_opts, "ip.zeromq.org", "fdf5:d058:d656::1");
}

static void test_dns_ipv6_only ()
{
    zmq::ip_resolver_options_t resolver_opts;

    resolver_opts
        .ipv6 (true)
        .allow_dns (true);

    test_resolve (resolver_opts, "ipv6only.zeromq.org", "fdf5:d058:d656::2");
}

static void test_dns_ipv6_invalid ()
{
    zmq::ip_resolver_options_t resolver_opts;

    resolver_opts
        .ipv6 (true)
        .allow_dns (true);

    test_resolve (resolver_opts, "invalid.zeromq.org", NULL);
}

static void test_dns_ipv6_ipv4 ()
{
    zmq::ip_resolver_options_t resolver_opts;

    resolver_opts
        .ipv6 (true)
        .allow_dns (true);

    //  If a host doesn't have an IPv6 then it should resolve as an embedded v4
    //  address in an IPv6
    test_resolve (resolver_opts, "ipv4only.zeromq.org", "::ffff:10.100.0.2");
}

static void test_dns_ipv6_numeric ()
{
    zmq::ip_resolver_options_t resolver_opts;

    resolver_opts
        .ipv6 (true)
        .allow_dns (true);

    //  Numeric IPs should still work
    test_resolve (resolver_opts, "fdf5:d058:d656::1", "fdf5:d058:d656::1");
}

static void test_dns_ipv6_port ()
{
    zmq::ip_resolver_options_t resolver_opts;

    resolver_opts
        .ipv6 (true)
        .expect_port (true)
        .allow_dns (true);

    test_resolve (resolver_opts, "ip.zeromq.org:1234", "fdf5:d058:d656::1",
                  1234);
}

void test_dns_brackets ()
{
    zmq::ip_resolver_options_t resolver_opts;

    resolver_opts
        .allow_dns (true);

    test_resolve (resolver_opts, "[ip.zeromq.org]", "10.100.0.1");
}

void test_dns_brackets_bad ()
{
    zmq::ip_resolver_options_t resolver_opts;

    resolver_opts
        .allow_dns (true);

    test_resolve (resolver_opts, "[ip.zeromq].org", NULL);
}

void test_dns_brackets_port ()
{
    zmq::ip_resolver_options_t resolver_opts;

    resolver_opts
        .allow_dns (true);

    test_resolve (resolver_opts, "[ip.zeromq.org]:22", "10.100.0.1", 22);
}

void test_dns_brackets_port_bad ()
{
    zmq::ip_resolver_options_t resolver_opts;

    resolver_opts
        .allow_dns (true);

    test_resolve (resolver_opts, "[ip.zeromq.org:22]", NULL);
}

void test_dns_deny (int ipv6_)
{
    zmq::ip_resolver_options_t resolver_opts;

    resolver_opts
        .allow_dns (false)
        .ipv6 (ipv6_);

    //  DNS resolution shouldn't work when disallowed
    test_resolve (resolver_opts, "ip.zeromq.org", NULL);
}
MAKE_TEST_V4V6(test_dns_deny)

void test_dns_ipv6_scope ()
{
    zmq::ip_resolver_options_t resolver_opts;

    resolver_opts
        .allow_dns (true)
        .ipv6 (true);

    //  Not sure if that's very useful but you could technically add a scope
    //  identifier to a hostname
    test_resolve (resolver_opts, "ip.zeromq.org%lo0", "fdf5:d058:d656::1", 0,
                  1);
}

void test_dns_ipv6_scope_port ()
{
    zmq::ip_resolver_options_t resolver_opts;

    resolver_opts
        .allow_dns (true)
        .expect_port (true)
        .ipv6 (true);

    //  Not sure if that's very useful but you could technically add a scope
    //  identifier to a hostname
    test_resolve (resolver_opts, "ip.zeromq.org%lo0:4444", "fdf5:d058:d656::1",
                  4444, 1);
}

void test_dns_ipv6_scope_port_brackets ()
{
    zmq::ip_resolver_options_t resolver_opts;

    resolver_opts
        .allow_dns (true)
        .expect_port (true)
        .ipv6 (true);

    test_resolve (resolver_opts, "[ip.zeromq.org%lo0]:4444",
                  "fdf5:d058:d656::1", 4444, 1);
}

int main (void)
{
    setup_test_environment ();

    UNITY_BEGIN ();

    RUN_TEST (test_bind_any_ipv4);
    RUN_TEST (test_bind_any_ipv6);
    RUN_TEST (test_nobind_any_ipv4);
    RUN_TEST (test_nobind_any_ipv6);
    RUN_TEST (test_nobind_any_port_ipv4);
    RUN_TEST (test_nobind_any_port_ipv6);
    RUN_TEST (test_nobind_addr_anyport_ipv4);
    RUN_TEST (test_nobind_addr_anyport_ipv6);
    RUN_TEST (test_parse_ipv4_simple);
    RUN_TEST (test_parse_ipv4_zero);
    RUN_TEST (test_parse_ipv4_max);
    RUN_TEST (test_parse_ipv4_brackets);
    RUN_TEST (test_parse_ipv4_brackets_missingl);
    RUN_TEST (test_parse_ipv4_brackets_missingr);
    RUN_TEST (test_parse_ipv4_brackets_bad);
    RUN_TEST (test_parse_ipv4_reject_port);
    RUN_TEST (test_parse_ipv4_reject_any);
    RUN_TEST (test_parse_ipv4_reject_ipv6);
    RUN_TEST (test_parse_ipv4_port);
    RUN_TEST (test_parse_ipv4_port0);
    RUN_TEST (test_parse_ipv4_port_garbage);
    RUN_TEST (test_parse_ipv4_port_missing);
    RUN_TEST (test_parse_ipv4_port_bad);
    RUN_TEST (test_parse_ipv4_port_brackets);
    RUN_TEST (test_parse_ipv4_port_brackets_bad);
    RUN_TEST (test_parse_ipv4_port_brackets_bad2);
    RUN_TEST (test_parse_ipv4_wild_brackets_bad);
    RUN_TEST (test_parse_ipv4_port_ipv6_reject);
    RUN_TEST (test_parse_ipv6_simple);
    RUN_TEST (test_parse_ipv6_simple2);
    RUN_TEST (test_parse_ipv6_zero);
    RUN_TEST (test_parse_ipv6_max);
    RUN_TEST (test_parse_ipv6_brackets);
    RUN_TEST (test_parse_ipv6_brackets_missingl);
    RUN_TEST (test_parse_ipv6_brackets_missingr);
    RUN_TEST (test_parse_ipv6_brackets_bad);
    RUN_TEST (test_parse_ipv6_port);
    RUN_TEST (test_parse_ipv6_port_any);
    RUN_TEST (test_parse_ipv6_port_nobrackets);
    RUN_TEST (test_parse_ipv4_in_ipv6);
    RUN_TEST (test_parse_ipv4_in_ipv6_port);
    RUN_TEST (test_parse_ipv6_scope_int);
    RUN_TEST (test_parse_ipv6_scope_zero);
    RUN_TEST (test_parse_ipv6_scope_int_port);
    RUN_TEST (test_parse_ipv6_scope_if);
    RUN_TEST (test_parse_ipv6_scope_if_port);
    RUN_TEST (test_parse_ipv6_scope_if_port_brackets);
    RUN_TEST (test_parse_ipv6_scope_if_port_brackets_bad);
    RUN_TEST (test_parse_ipv6_scope_badif);
    RUN_TEST (test_dns_ipv4_simple);
    RUN_TEST (test_dns_ipv4_only);
    RUN_TEST (test_dns_ipv4_invalid);
    RUN_TEST (test_dns_ipv4_ipv6);
    RUN_TEST (test_dns_ipv4_numeric);
    RUN_TEST (test_dns_ipv4_port);
    RUN_TEST (test_dns_ipv6_simple);
    RUN_TEST (test_dns_ipv6_only);
    RUN_TEST (test_dns_ipv6_invalid);
    RUN_TEST (test_dns_ipv6_ipv4);
    RUN_TEST (test_dns_ipv6_numeric);
    RUN_TEST (test_dns_ipv6_port);
    RUN_TEST (test_dns_brackets);
    RUN_TEST (test_dns_brackets_bad);
    RUN_TEST (test_dns_deny_ipv4);
    RUN_TEST (test_dns_deny_ipv6);
    RUN_TEST (test_dns_ipv6_scope);
    RUN_TEST (test_dns_ipv6_scope_port);
    RUN_TEST (test_dns_ipv6_scope_port_brackets);

    return UNITY_END ();
}
