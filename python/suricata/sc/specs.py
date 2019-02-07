argsd = {
    "pcap-file": [
        {
            "name": "filename",
            "required": 1,
        },
        {
            "name": "output-dir",
            "required": 1,
        },
        {
            "name": "tenant",
            "type": int,
            "required": 0,
        },
        {
            "name": "continuous",
            "required": 0,
        },
        {
            "name": "delete-when-done",
            "required": 0,
        },
    ],
    "pcap-file-continuous": [
        {
            "name": "filename",
            "required": 1,
        },
        {
            "name": "output-dir",
            "required": 1,
        },
        {
            "name": "tenant",
            "type": int,
            "required": 0,
        },
        {
            "name": "delete-when-done",
            "required": 0,
        },
    ],
    "iface-stat": [
        {
            "name": "iface",
            "required": 1,
        },
    ],
    "conf-get": [
        {
            "name": "variable",
            "required": 1,
        }
    ],
    "unregister-tenant-handler": [
        {
            "name": "tenantid",
            "required": 1,
        },
        {
            "name": "htype",
            "required": 1,
        },
        {
            "name": "hargs",
            "type": int,
            "required": 0,
        },
    ],
    "register-tenant-handler": [
        {
            "name": "tenantid",
            "required": 1,
        },
        {
            "name": "htype",
            "required": 1,
        },
        {
            "name": "hargs",
            "type": int,
            "required": 0,
        },
    ],
    "unregister-tenant": [
        {
            "name": "id",
            "type": int,
            "required": 1,
        },
    ],
    "register-tenant": [
        {
            "name": "id",
            "type": int,
            "required": 1,
        },
        {
            "name": "filename",
            "required": 1,
        },
    ],
    "reload-tenant": [
        {
            "name": "id",
            "type": int,
            "required": 1,
        },
        {
            "name": "filename",
            "required": 1,
        },
    ],
    "add-hostbit": [
        {
            "name": "ipaddress",
            "required": 1,
        },
        {
            "name": "hostbit",
            "required": 1,
        },
        {
            "name": "expire",
            "type": int,
            "required": 1,
        },
    ],
    "remove-hostbit": [
        {
            "name": "ipaddress",
            "required": 1,
        },
        {
            "name": "hostbit",
            "required": 1,
        },
    ],
    "list-hostbit": [
        {
            "name": "ipaddress",
            "required": 1,
        },
    ],
    "memcap-set": [
        {
            "name": "config",
            "required": 1,
        },
        {
            "name": "memcap",
            "required": 1,
        },
    ],
    "memcap-show": [
        {
            "name": "config",
            "required": 1,
        },
    ],
    }
