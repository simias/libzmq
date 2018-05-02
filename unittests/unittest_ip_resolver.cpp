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

//  Generate an invalid but well-defined 'ip_addr_t'. Avoids testing
//  uninitialized values if the code is buggy.
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

void test_bind_any (int ipv6_)
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

void test_bind_any_ipv4 () {
    test_bind_any (false);
}

void test_bind_any_ipv6 () {
    test_bind_any (true);
}

void test_nobind_any (int ipv6_)
{
    zmq::ip_resolver_options_t resolver_opts;
    zmq::ip_addr_t addr = test_bad_addr ();

    resolver_opts
        .bindable (false)
        .allow_dns (false)
        .allow_nic_name (false)
        .expect_port (true)
        .ipv6 (ipv6_);

    test_ip_resolver_t resolver (resolver_opts);

    //  Wildcard should be rejected if we're not looking for a
    //  bindable address
    TEST_ASSERT_EQUAL(-1, resolver.resolve(&addr, "*:*"));
    TEST_ASSERT_EQUAL(-1, resolver.resolve(&addr, "*:1234"));

    // This however works. Should it ? For the time being I'm going to
    // keep it that way for backcompat but I can't imagine why you'd
    // want a wildcard port if you're not binding.
    TEST_ASSERT_EQUAL(0, resolver.resolve(&addr, "127.0.0.1:*"));
}

void test_nobind_any_ipv4 () {
    test_nobind_any (false);
}

void test_nobind_any_ipv6 () {
    test_nobind_any (true);
}

void test_parse_ipv4_simple () {
    zmq::ip_resolver_options_t resolver_opts;
    zmq::ip_addr_t addr;
    struct in_addr expected_addr;

    resolver_opts
        .bindable (false)
        .allow_dns (false)
        .allow_nic_name (false)
        .expect_port (false)
        .ipv6 (false);

    test_ip_resolver_t resolver (resolver_opts);

    assert (test_inet_pton (AF_INET, "1.2.128.129", &expected_addr) == 1);

    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (0, resolver.resolve(&addr, "1.2.128.129"));
    validate_ipv4_addr (addr, expected_addr);

    //  Not particularly useful, but valid
    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (0, resolver.resolve(&addr, "[1.2.128.129]"));
    validate_ipv4_addr (addr, expected_addr);

    TEST_ASSERT_EQUAL (-1, resolver.resolve(&addr, "[1.2.128].129"));
    TEST_ASSERT_EQUAL (-1, resolver.resolve(&addr, "[1.2.128.]129"));
    TEST_ASSERT_EQUAL (-1, resolver.resolve(&addr, "[1.2.128.129"));
    TEST_ASSERT_EQUAL (-1, resolver.resolve(&addr, "1.2.128.129]"));

    //  No port expected, should be rejected
    TEST_ASSERT_EQUAL (-1, resolver.resolve(&addr, "1.2.128.129:123"));
    TEST_ASSERT_EQUAL (-1, resolver.resolve(&addr, "1.2.128.129:*"));

    //  IPv6 should be rejected
    TEST_ASSERT_EQUAL (-1, resolver.resolve(&addr, "::1"));
}

void test_parse_ipv4_port () {
    zmq::ip_resolver_options_t resolver_opts;
    zmq::ip_addr_t addr;
    struct in_addr expected_addr;

    resolver_opts
        .bindable (false)
        .allow_dns (false)
        .allow_nic_name (false)
        .expect_port (true)
        .ipv6 (false);

    test_ip_resolver_t resolver (resolver_opts);

    assert (test_inet_pton (AF_INET, "1.2.128.129", &expected_addr) == 1);

    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (0, resolver.resolve(&addr, "1.2.128.129:123"));
    validate_ipv4_addr (addr, expected_addr, 123);

    //  The code doesn't validate that the port doesn't contain garbage, should
    //  it?
    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (0, resolver.resolve(&addr, "1.2.128.129:123bad"));
    validate_ipv4_addr (addr, expected_addr, 123);

    TEST_ASSERT_EQUAL (-1, resolver.resolve(&addr, "1.2.128.129"));
    TEST_ASSERT_EQUAL (-1, resolver.resolve(&addr, "1.2.128.129:bad"));

    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (0, resolver.resolve(&addr, "[1.2.128.129]:123"));
    validate_ipv4_addr (addr, expected_addr, 123);

    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (0, resolver.resolve(&addr, "1.2.128.129:*"));
    validate_ipv4_addr (addr, expected_addr, 0);

    TEST_ASSERT_EQUAL (-1, resolver.resolve(&addr, "[1.2.128.129:]123"));
    TEST_ASSERT_EQUAL (-1, resolver.resolve(&addr, "[1.2.128.]129"));
    TEST_ASSERT_EQUAL (-1, resolver.resolve(&addr, "[1.2.128].129"));
    TEST_ASSERT_EQUAL (-1, resolver.resolve(&addr, "[1.2.128]129"));
    TEST_ASSERT_EQUAL (-1, resolver.resolve(&addr, "[1.2.128.129:123]"));
    TEST_ASSERT_EQUAL (-1, resolver.resolve(&addr, "[1.2.128.129:*]"));

    //  IPv6 should be rejected
    TEST_ASSERT_EQUAL (-1, resolver.resolve(&addr, "[::1]:1234"));
}

void test_parse_ipv6_simple () {
    zmq::ip_resolver_options_t resolver_opts;
    zmq::ip_addr_t addr;
    struct in6_addr expected_addr;

    resolver_opts
        .bindable (false)
        .allow_dns (false)
        .allow_nic_name (false)
        .expect_port (false)
        .ipv6 (true);

    test_ip_resolver_t resolver (resolver_opts);

    assert (test_inet_pton (AF_INET6, "::1", &expected_addr) == 1);

    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (0, resolver.resolve(&addr, "::1"));
    validate_ipv6_addr (addr, expected_addr);

    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (0, resolver.resolve(&addr, "[::1]"));
    validate_ipv6_addr (addr, expected_addr);

    assert (test_inet_pton (AF_INET6, "abcd:1234::1:0:234", &expected_addr) == 1);

    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (0, resolver.resolve(&addr, "abcd:1234::1:0:234"));
    validate_ipv6_addr (addr, expected_addr);

    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (0, resolver.resolve(&addr, "[abcd:1234::1:0:234]"));
    validate_ipv6_addr (addr, expected_addr);

    TEST_ASSERT_EQUAL (-1, resolver.resolve(&addr, "[abcd:1234::1]:0:234"));
    TEST_ASSERT_EQUAL (-1, resolver.resolve(&addr, "[abcd:1234::1:0]:234"));
    TEST_ASSERT_EQUAL (-1, resolver.resolve(&addr, "[abcd:1234::1:0:]234"));
    TEST_ASSERT_EQUAL (-1, resolver.resolve(&addr, "[abcd:1234::1:0:234"));
    TEST_ASSERT_EQUAL (-1, resolver.resolve(&addr, "abcd:1234::1:0:234]"));
}

void test_parse_ipv6_port () {
    zmq::ip_resolver_options_t resolver_opts;
    zmq::ip_addr_t addr;
    struct in6_addr expected_addr;

    resolver_opts
        .bindable (false)
        .allow_dns (false)
        .allow_nic_name (false)
        .expect_port (true)
        .ipv6 (true);

    test_ip_resolver_t resolver (resolver_opts);

    assert (test_inet_pton (AF_INET6, "abcd:1234::1:0:234",
                            &expected_addr) == 1);

    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (0, resolver.resolve(&addr, "[abcd:1234::1:0:234]:*"));
    validate_ipv6_addr (addr, expected_addr, 0);

    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (0, resolver.resolve(&addr, "[abcd:1234::1:0:234]:5432"));
    validate_ipv6_addr (addr, expected_addr, 5432);

    TEST_ASSERT_EQUAL (-1, resolver.resolve(&addr, "[::1]:123:456"));

    //  Should this be allowed? Seems error-prone but so far ZMQ accepts it.
    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (0, resolver.resolve(&addr, "abcd:1234::1:0:234:123"));
    validate_ipv6_addr (addr, expected_addr, 123);
}

//  Parsing IPv4 should also work if an IPv6 is requested, it
//  returns an IPv6 with the IPv4 address embedded
void test_parse_ipv4_in_ipv6_simple ()
{
    zmq::ip_resolver_options_t resolver_opts;
    zmq::ip_addr_t addr;
    struct in6_addr expected_addr;

    resolver_opts
        .bindable (false)
        .allow_dns (false)
        .allow_nic_name (false)
        .expect_port (false)
        .ipv6 (true);

    test_ip_resolver_t resolver (resolver_opts);

    assert (test_inet_pton (AF_INET6, "::ffff:1.2.128.129", &expected_addr) == 1);

    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (0, resolver.resolve(&addr, "1.2.128.129"));
    validate_ipv6_addr (addr, expected_addr);

    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (0, resolver.resolve(&addr, "::ffff:1.2.128.129"));
    validate_ipv6_addr (addr, expected_addr);

    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (0, resolver.resolve(&addr, "[1.2.128.129]"));
    validate_ipv6_addr (addr, expected_addr);

    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (0, resolver.resolve(&addr, "[::ffff:1.2.128.129]"));
    validate_ipv6_addr (addr, expected_addr);
}

void test_parse_ipv4_in_ipv6_port ()
{
    zmq::ip_resolver_options_t resolver_opts;
    zmq::ip_addr_t addr;
    struct in6_addr expected_addr;

    resolver_opts
        .bindable (false)
        .allow_dns (false)
        .allow_nic_name (false)
        .expect_port (true)
        .ipv6 (true);

    test_ip_resolver_t resolver (resolver_opts);

    assert (test_inet_pton (AF_INET6, "::ffff:1.2.128.129", &expected_addr) == 1);

    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (0, resolver.resolve(&addr, "1.2.128.129:1234"));
    validate_ipv6_addr (addr, expected_addr, 1234);

    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (0, resolver.resolve(&addr, "[1.2.128.129]:1234"));
    validate_ipv6_addr (addr, expected_addr, 1234);

    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (0, resolver.resolve(&addr, "1.2.128.129:*"));
    validate_ipv6_addr (addr, expected_addr, 0);

    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (0, resolver.resolve(&addr, "[::ffff:1.2.128.129]:1234"));
    validate_ipv6_addr (addr, expected_addr, 1234);
}

void test_parse_ipv6_scope_simple ()
{
    zmq::ip_resolver_options_t resolver_opts;
    zmq::ip_addr_t addr;
    struct in6_addr expected_addr;

    resolver_opts
        .bindable (false)
        .allow_dns (false)
        .allow_nic_name (false)
        .expect_port (false)
        .ipv6 (true);

    test_ip_resolver_t resolver (resolver_opts);

    assert (test_inet_pton (AF_INET6, "3000:4:5::1:234", &expected_addr) == 1);

    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (0, resolver.resolve(&addr, "3000:4:5::1:234%1"));
    validate_ipv6_addr (addr, expected_addr, 0, 1);

    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (0, resolver.resolve(&addr, "3000:4:5::1:234%2"));
    validate_ipv6_addr (addr, expected_addr, 0, 2);

    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (-1, resolver.resolve(&addr, "3000:4:5::1:234%0"));

#ifdef HAVE_IFNAMETOINDEX
    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (0, resolver.resolve(&addr, "3000:4:5::1:234%lo0"));
    validate_ipv6_addr (addr, expected_addr, 0, 1);

    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (0, resolver.resolve(&addr, "3000:4:5::1:234%eth0"));
    validate_ipv6_addr (addr, expected_addr, 0, 2);

    TEST_ASSERT_EQUAL (-1, resolver.resolve(&addr, "3000:4:5::1:234%bad0"));
#endif // HAVE_IFNAMETOINDEX
}

void test_parse_ipv6_scope_port ()
{
    zmq::ip_resolver_options_t resolver_opts;
    zmq::ip_addr_t addr;
    struct in6_addr expected_addr;

    resolver_opts
        .bindable (false)
        .allow_dns (false)
        .allow_nic_name (false)
        .expect_port (true)
        .ipv6 (true);

    test_ip_resolver_t resolver (resolver_opts);

    assert (test_inet_pton (AF_INET6, "3000:4:5::1:234", &expected_addr) == 1);

    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (0, resolver.resolve(&addr, "3000:4:5::1:234%1:123"));
    validate_ipv6_addr (addr, expected_addr, 123, 1);

    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (0, resolver.resolve(&addr, "[3000:4:5::1:234%2]:123"));
    validate_ipv6_addr (addr, expected_addr, 123, 2);

    TEST_ASSERT_EQUAL (-1, resolver.resolve(&addr, "[3000:4:5::1:234]%2:123"));

#ifdef HAVE_IFNAMETOINDEX
    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (0, resolver.resolve(&addr, "3000:4:5::1:234%lo0:456"));
    validate_ipv6_addr (addr, expected_addr, 456, 1);

    addr = test_bad_addr ();
    TEST_ASSERT_EQUAL (0, resolver.resolve(&addr, "[3000:4:5::1:234%eth0]:22"));
    validate_ipv6_addr (addr, expected_addr, 22, 2);

    TEST_ASSERT_EQUAL (-1, resolver.resolve(&addr, "[3000:4:5::1:234]%bad0:44"));
#endif // HAVE_IFNAMETOINDEX
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

    test_ip_resolver_t resolver (resolver_opts);

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

    test_ip_resolver_t resolver (resolver_opts);

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

    test_ip_resolver_t resolver (resolver_opts);

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

    test_ip_resolver_t resolver (resolver_opts);

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

    test_ip_resolver_t resolver (resolver_opts);

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

    test_ip_resolver_t resolver (resolver_opts);

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

    test_ip_resolver_t resolver (resolver_opts);

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

    test_ip_resolver_t resolver (resolver_opts);

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

    test_ip_resolver_t resolver (resolver_opts);

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

    RUN_TEST (test_bind_any_ipv4);
    RUN_TEST (test_nobind_any_ipv4);
    RUN_TEST (test_parse_ipv4_simple);
    RUN_TEST (test_parse_ipv4_port);
    RUN_TEST (test_dns_ipv4_simple);
    RUN_TEST (test_dns_ipv4_port);
    RUN_TEST (test_dns_ipv4_deny);


    if (is_ipv6_available ()) {
        RUN_TEST (test_bind_any_ipv6);
        RUN_TEST (test_nobind_any_ipv6);
        RUN_TEST (test_parse_ipv6_simple);
        RUN_TEST (test_parse_ipv6_port);
        RUN_TEST (test_parse_ipv4_in_ipv6_simple);
        RUN_TEST (test_parse_ipv4_in_ipv6_port);
        RUN_TEST (test_parse_ipv6_scope_simple);
        RUN_TEST (test_parse_ipv6_scope_port);
        RUN_TEST (test_dns_ipv6_deny);
        RUN_TEST (test_dns_ipv6_simple);
        RUN_TEST (test_dns_ipv6_scope);
        RUN_TEST (test_dns_ipv6_port);
        RUN_TEST (test_dns_ipv4_in_ipv6_simple);
        RUN_TEST (test_dns_ipv4_in_ipv6_port);
    }

    return UNITY_END ();
}
