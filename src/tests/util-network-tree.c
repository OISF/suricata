/* Copyright (C) 2018 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Giuseppe Longo <glongo@stamus-networks.com>
 *
 * Tests for network tree code.
 */

#include "../suricata-common.h"
#include "../util-network-tree.h"

static int NetworkTreeTest01(void)
{
    const char *js = "[{\"name\":\"User networks\", \"children\":[{\"name\":\"Italy\", \"children\":[{\"name\": \"Lecce\", \"addresses\":[\"192.168.1.176\"]}]}]}]";
    json_t *networkjs = json_loads(js, 0, NULL);
    FAIL_IF(networkjs == NULL);

    Packet *p = UTHBuildPacketSrcDst(NULL, 0, IPPROTO_TCP, "192.168.1.176", "192.168.1.1");
    FAIL_IF_NULL(p);

    NetworkTreeInitForTests(networkjs);

    json_t *resultjs = NetworkTreeGetIPv4InfoAsJSON((uint8_t *)GET_IPV4_SRC_ADDR_PTR(p), p->tenant_id);
    FAIL_IF(resultjs == NULL);

    const char *results[] = { "Lecce", "Italy", "User networks" };
    size_t size;
    json_t *elem;
    int i = 0;

    json_array_foreach(resultjs, size, elem) {
        FAIL_IF(strcmp(results[i], json_string_value(elem)) != 0);
        i++;
    }

    json_decref(resultjs);
    json_decref(networkjs);
    UTHFreePacket(p);
    NetworkTreeDeInit();

    PASS;
}

static int NetworkTreeTest02(void)
{
    const char *js = "[{\"name\":\"User networks\", \"addresses\":[\"192.168.1.0/24\"], \"children\":[{\"name\":\"Italy\", \"children\":[{\"name\": \"Lecce\", \"addresses\":[\"192.168.1.176\"]}]}]}]";
    json_t *networkjs = json_loads(js, 0, NULL);
    FAIL_IF(networkjs == NULL);

    Packet *p = UTHBuildPacketSrcDst(NULL, 0, IPPROTO_TCP, "192.168.1.2", "192.168.1.1");
    FAIL_IF_NULL(p);

    NetworkTreeInitForTests(networkjs);

    json_t *resultjs = NetworkTreeGetIPv4InfoAsJSON((uint8_t *)GET_IPV4_SRC_ADDR_PTR(p), p->tenant_id);
    FAIL_IF(resultjs == NULL);

    const char *result = "User networks";
    size_t size;
    json_t *elem;

    json_array_foreach(resultjs, size, elem) {
        FAIL_IF(strcmp(result, json_string_value(elem)) != 0);
    }

    json_decref(resultjs);
    json_decref(networkjs);
    UTHFreePacket(p);
    NetworkTreeDeInit();

    PASS;
}

static int NetworkTreeTest03(void)
{
    const char *js = "[{\"name\":\"User networks\", \"addresses\":[\"192.168.1.0/24\"], \"children\":[{\"name\":\"Italy\", \"addresses\":[\"192.168.1.175\"], \"children\":[{\"name\": \"Lecce\", \"addresses\":[\"192.168.1.176\"]}]}]}]";
    json_t *networkjs = json_loads(js, 0, NULL);
    FAIL_IF(networkjs == NULL);

    Packet *p = UTHBuildPacketSrcDst(NULL, 0, IPPROTO_TCP, "192.168.1.175", "192.168.1.1");
    FAIL_IF_NULL(p);

    NetworkTreeInitForTests(networkjs);

    json_t *resultjs = NetworkTreeGetIPv4InfoAsJSON((uint8_t *)GET_IPV4_SRC_ADDR_PTR(p), p->tenant_id);
    FAIL_IF(resultjs == NULL);

    const char *results[] = { "Italy", "User networks" };
    size_t size;
    json_t *elem;
    int i = 0;

    json_array_foreach(resultjs, size, elem) {
        FAIL_IF(strcmp(results[i], json_string_value(elem)) != 0);
        i++;
    }

    json_decref(resultjs);
    json_decref(networkjs);
    UTHFreePacket(p);
    NetworkTreeDeInit();

    PASS;
}

static int NetworkTreeTest04(void)
{
    const char *js = "[{\"name\": \"Private class A\", \"addresses\": [\"10.0.0.0/8\"]}, {\"name\": \"Private class B\", \"addresses\": [\"172.16.0.0/12\"]}, {\"name\": \"Private class C\", \"addresses\": [\"192.168.0.0/16\"]}]";
    json_t *networkjs = json_loads(js, 0, NULL);
    FAIL_IF(networkjs == NULL);

    Packet *p = UTHBuildPacketSrcDst(NULL, 0, IPPROTO_TCP, "10.0.0.2", "10.0.0.1");
    FAIL_IF_NULL(p);

    NetworkTreeInitForTests(networkjs);

    json_t *resultjs = NetworkTreeGetIPv4InfoAsJSON((uint8_t *)GET_IPV4_SRC_ADDR_PTR(p), p->tenant_id);
    FAIL_IF(resultjs == NULL);

    const char *result = "Private class A";
    size_t size;
    json_t *elem;

    json_array_foreach(resultjs, size, elem) {
        FAIL_IF(strcmp(result, json_string_value(elem)) != 0);
    }

    json_decref(resultjs);
    json_decref(networkjs);
    UTHFreePacket(p);
    NetworkTreeDeInit();

    PASS;
}

static int NetworkTreeTest05(void)
{
    const char *js = "[{\"name\": \"Private class A\", \"addresses\": [\"10.0.0.0/8\"]}, {\"name\": \"Private class B\", \"addresses\": [\"172.16.0.0/12\"]}, {\"name\": \"Private class C\", \"addresses\": [\"192.168.0.0/16\"]}]";
    json_t *networkjs = json_loads(js, 0, NULL);
    FAIL_IF(networkjs == NULL);

    Packet *p = UTHBuildPacketSrcDst(NULL, 0, IPPROTO_TCP, "172.16.0.2", "172.16.0.1");
    FAIL_IF_NULL(p);

    NetworkTreeInitForTests(networkjs);

    json_t *resultjs = NetworkTreeGetIPv4InfoAsJSON((uint8_t *)GET_IPV4_SRC_ADDR_PTR(p), p->tenant_id);
    FAIL_IF(resultjs == NULL);

    const char *result = "Private class B";
    size_t size;
    json_t *elem;

    json_array_foreach(resultjs, size, elem) {
        FAIL_IF(strcmp(result, json_string_value(elem)) != 0);
    }

    json_decref(resultjs);
    json_decref(networkjs);
    UTHFreePacket(p);
    NetworkTreeDeInit();

    PASS;
}

static int NetworkTreeTest06(void)
{
    const char *js = "[{\"name\": \"Private class A\", \"addresses\": [\"10.0.0.0/8\"]}, {\"name\": \"Private class B\", \"addresses\": [\"172.16.0.0/12\"]}, {\"name\": \"Private class C\", \"addresses\": [\"192.168.0.0/16\"]}]";
    json_t *networkjs = json_loads(js, 0, NULL);
    FAIL_IF(networkjs == NULL);

    Packet *p = UTHBuildPacketSrcDst(NULL, 0, IPPROTO_TCP, "192.168.0.2", "192.168.0.1");
    FAIL_IF_NULL(p);

    NetworkTreeInitForTests(networkjs);

    json_t *resultjs = NetworkTreeGetIPv4InfoAsJSON((uint8_t *)GET_IPV4_SRC_ADDR_PTR(p), p->tenant_id);
    FAIL_IF(resultjs == NULL);

    const char *result = "Private class C";
    size_t size;
    json_t *elem;

    json_array_foreach(resultjs, size, elem) {
        FAIL_IF(strcmp(result, json_string_value(elem)) != 0);
    }

    json_decref(resultjs);
    json_decref(networkjs);
    UTHFreePacket(p);
    NetworkTreeDeInit();

    PASS;
}

static int NetworkTreeTest07(void)
{
    const char *js = "[{\"name\": \"XS\", \"children\": [{\"name\": \"Red team\", \"addresses\":[\"192.168.17.0/24\"]}, {\"name\": \"Crimsonia\", \"addresses\":[\"198.18.2.0/24\",\"198.18.3.0/24\",\"10.242.4.0/24\",\"10.242.5.0/24\",\"10.242.6.0/24\",\"198.18.0.0/24\",\"2a07:1181:130:3602::/64\",\"2a07:1181:130:3603::/64\",\"2a07:1181:130:3604::/64\",\"2a07:1181:130:3605::/64\",\"2a07:1181:130:3606::/64\",\"2a07:1181:130:3607::/64\"]}, {\"name\": \"Internet\", \"addresses\":[\"0.0.0.0/0\",\"0::/0\"]}]}]";
    json_t *networkjs = json_loads(js, 0, NULL);
    FAIL_IF(networkjs == NULL);

    Packet *p = UTHBuildPacketSrcDst(NULL, 0, IPPROTO_TCP, "100.116.103.160", "198.18.2.5");
    FAIL_IF_NULL(p);

    NetworkTreeInitForTests(networkjs);

    p->tenant_id = 0;
    json_t *resultjs = NetworkTreeGetIPv4InfoAsJSON((uint8_t *)GET_IPV4_SRC_ADDR_PTR(p), p->tenant_id);
    FAIL_IF(resultjs == NULL);

    const char *results[] = { "Internet", "XS" };
    size_t size;
    json_t *elem;
    int i = 0;

    json_array_foreach(resultjs, size, elem) {
        FAIL_IF(strcmp(results[i], json_string_value(elem)) != 0);
        i++;
    }

    json_decref(resultjs);
    json_decref(networkjs);
    UTHFreePacket(p);
    NetworkTreeDeInit();

    PASS;
}

void NetworkTreeDoRegisterTests(void)
{
    UtRegisterTest("NetworkTreeTest01", NetworkTreeTest01);
    UtRegisterTest("NetworkTreeTest02", NetworkTreeTest02);
    UtRegisterTest("NetworkTreeTest03", NetworkTreeTest03);
    UtRegisterTest("NetworkTreeTest04", NetworkTreeTest04);
    UtRegisterTest("NetworkTreeTest05", NetworkTreeTest05);
    UtRegisterTest("NetworkTreeTest06", NetworkTreeTest06);
    UtRegisterTest("NetworkTreeTest07", NetworkTreeTest07);
}

