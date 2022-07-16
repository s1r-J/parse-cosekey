import { test } from 'tap';
import crypto from 'crypto';
import str2ab from 'str2ab';
import KeyParser from '../dist/keyParser';

const ES256 = {
  COSE_MAP: new Map<number, any>()
    .set(1, 2)
    .set(3, -7)
    .set(-1, 1)
    .set(
      -2,
      Buffer.from([
        0xe7, 0x64, 0xeb, 0xad, 0x3b, 0xf0, 0x03, 0x87, 0x46, 0x99, 0xb7, 0xc5, 0x41, 0xce, 0x94, 0x79, 0x6a, 0x17,
        0xac, 0xd6, 0x53, 0xeb, 0x58, 0x28, 0xba, 0x2f, 0x40, 0xa3, 0xe3, 0x4b, 0xf7, 0xdb,
      ]),
    )
    .set(
      -3,
      Buffer.from([
        0x93, 0xc3, 0xdf, 0xd7, 0x10, 0xee, 0x2c, 0xb4, 0x43, 0x4e, 0x27, 0xd5, 0x42, 0x50, 0x2e, 0x82, 0xef, 0x5f,
        0x2c, 0xa0, 0xef, 0xe8, 0xde, 0xd8, 0x1d, 0xce, 0x9d, 0xad, 0xbc, 0x1a, 0x40, 0x2c,
      ]),
    ),
  JWK: {
    kty: 'EC',
    alg: 'ES256',
    crv: 'P-256',
    x: str2ab.base642buffer('52TrrTvwA4dGmbfFQc6UeWoXrNZT61goui9Ao+NL99s='),
    y: str2ab.base642buffer('k8Pf1xDuLLRDTifVQlAugu9fLKDv6N7YHc6drbwaQCw='),
  },
  PEM: `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE52TrrTvwA4dGmbfFQc6UeWoXrNZT
61goui9Ao+NL99uTw9/XEO4stENOJ9VCUC6C718soO/o3tgdzp2tvBpALA==
-----END PUBLIC KEY-----
`,
  ATTESTATION_OBJECT: str2ab.base64url2buffer(
    'o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEgwRgIhAP8GpebSNIp6hRSWD0C5-Rby7WaGEqqqilyfmwxKd8hvAiEAr2-HMPgLjTA7VgNpvh32xdsmXAf-cbJBgG1Hv3UtVENjeDVjgVkB3zCCAdswggF9oAMCAQICAQEwDQYJKoZIhvcNAQELBQAwYDELMAkGA1UEBhMCVVMxETAPBgNVBAoMCENocm9taXVtMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMRowGAYDVQQDDBFCYXRjaCBDZXJ0aWZpY2F0ZTAeFw0xNzA3MTQwMjQwMDBaFw00MTEyMDExNTIxMTRaMGAxCzAJBgNVBAYTAlVTMREwDwYDVQQKDAhDaHJvbWl1bTEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEaMBgGA1UEAwwRQmF0Y2ggQ2VydGlmaWNhdGUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASNYX5lyVCOZLzFZzrIKmeZ2jwURmgsJYxGP__fWN_S-j5sN4tT15XEpN_7QZnt14YvI6uvAgO0uJEboFaZlOEBoyUwIzATBgsrBgEEAYLlHAIBAQQEAwIFIDAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA0kAMEYCIQCvDWiYl9lric6PkfYkH812bRT6UyMZ0QruejnnoK2X2gIhALkk2RmA8ZTXFtX3hpFt46nKGSmK5llg59g38u062C5WaGF1dGhEYXRhWKR0puqSE8mcL3SyJJKzIM9AJiqUwalQoDl_KSULYIQe8EUAAAABAQIDBAUGBwgBAgMEBQYHCAAgLAZo3VcNKR1y2xRLmEhbKYeOAo4zmr3pIzhZne9s0MSlAQIDJiABIVgg52TrrTvwA4dGmbfFQc6UeWoXrNZT61goui9Ao-NL99siWCCTw9_XEO4stENOJ9VCUC6C718soO_o3tgdzp2tvBpALA',
  ),
};

const PS384 = {
  COSE_MAP: new Map<number, any>()
    .set(1, 3)
    .set(3, -38)
    .set(
      -1,
      str2ab.base642buffer(
        '5BvghPzxrftCxA55bImJXlgGO+xTNlK8VqLsHpT0lgDz0CdwbRyMAOee6h4sLc2OVlODMbNyUQWz8keM0UNmvU0GFhxkZrd1D9XeUJXTlETNl7ukvs8tbUybsa+V3Gd5lh+cNy4X36cnHyoSL2kjIouUucVGCdmS45FdFk1bsrUBcuEGhMEaR/rbCFW71ZT9U4wM7LWDwp/tgFK0vsjGXvGcR4XTBjpsUxPmaWESaWDs+lE9doboeAFg4O7/GF9t3nr7RvIeTXBJhihDGQPo87HZomQ8X1fgtcbZ5wlQ9iPgV3X0llUSKjoktdkZdkWoWcuP2MBA/JblG715GJ4J5Q==',
      ),
    )
    .set(-2, str2ab.base642buffer('AQAB')),
  JWK: {
    kty: 'RSA',
    alg: 'PS384',
    n: '5BvghPzxrftCxA55bImJXlgGO-xTNlK8VqLsHpT0lgDz0CdwbRyMAOee6h4sLc2OVlODMbNyUQWz8keM0UNmvU0GFhxkZrd1D9XeUJXTlETNl7ukvs8tbUybsa-V3Gd5lh-cNy4X36cnHyoSL2kjIouUucVGCdmS45FdFk1bsrUBcuEGhMEaR_rbCFW71ZT9U4wM7LWDwp_tgFK0vsjGXvGcR4XTBjpsUxPmaWESaWDs-lE9doboeAFg4O7_GF9t3nr7RvIeTXBJhihDGQPo87HZomQ8X1fgtcbZ5wlQ9iPgV3X0llUSKjoktdkZdkWoWcuP2MBA_JblG715GJ4J5Q',
    e: 'AQAB',
  },
  PEM: `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5BvghPzxrftCxA55bImJ
XlgGO+xTNlK8VqLsHpT0lgDz0CdwbRyMAOee6h4sLc2OVlODMbNyUQWz8keM0UNm
vU0GFhxkZrd1D9XeUJXTlETNl7ukvs8tbUybsa+V3Gd5lh+cNy4X36cnHyoSL2kj
IouUucVGCdmS45FdFk1bsrUBcuEGhMEaR/rbCFW71ZT9U4wM7LWDwp/tgFK0vsjG
XvGcR4XTBjpsUxPmaWESaWDs+lE9doboeAFg4O7/GF9t3nr7RvIeTXBJhihDGQPo
87HZomQ8X1fgtcbZ5wlQ9iPgV3X0llUSKjoktdkZdkWoWcuP2MBA/JblG715GJ4J
5QIDAQAB
-----END PUBLIC KEY-----
`,
  ATTESTATION_OBJECT: str2ab.base64url2buffer(
    'o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZzglY3NpZ1kBAER0F31MoU5K9VvpiExwf2xUPeG_689_A0I5q8tEsruRIkF5fzWA1Uk8P4qlHwF9MOb5IU8jslnNQqtLQKv_fFgYXgERo_uts5GkWvZ8nWLrVUi_8cK1bpxF-PzzZaPt1g1Rk8Q2x7QPBW0ip_fKTnBTGfNhxO-OU3GncGj80t-_YMUsip_8b6raGCv9eOvXFIGR1qMbqmlqCSetoCyYKxQ6qC13tjuhpkcHwdOdSIdvd9IhFASC5EX3pRdiS2mvMDgcT6CfbjDPnq4wA5eBTVYjDv4Ibxc6omdz8K99em-flVLqxs0tSdfv9ddzo5lElhExMEP67Y-Op9BLwHvdLn9oYXV0aERhdGFZAWZJlg3liA6MaHQ0Fw9kdmBbj-SuuaKGMseZXPO6gx2XY0EAAAByBuy6aWZcQpm9f0NUYyTRzQAggJUd8LuTH3oDMKhNP85PN-VbPr1l5iuYBKzuJGLUQr-kAQMDOCUgWQEA5BvghPzxrftCxA55bImJXlgGO-xTNlK8VqLsHpT0lgDz0CdwbRyMAOee6h4sLc2OVlODMbNyUQWz8keM0UNmvU0GFhxkZrd1D9XeUJXTlETNl7ukvs8tbUybsa-V3Gd5lh-cNy4X36cnHyoSL2kjIouUucVGCdmS45FdFk1bsrUBcuEGhMEaR_rbCFW71ZT9U4wM7LWDwp_tgFK0vsjGXvGcR4XTBjpsUxPmaWESaWDs-lE9doboeAFg4O7_GF9t3nr7RvIeTXBJhihDGQPo87HZomQ8X1fgtcbZ5wlQ9iPgV3X0llUSKjoktdkZdkWoWcuP2MBA_JblG715GJ4J5SFDAQAB',
  ),
};

const RS1 = {
  COSE_MAP: new Map<number, any>()
    .set(1, 3)
    .set(3, -65535)
    .set(
      -1,
      str2ab.base642buffer(
        'zgdFL1k1ceZc+wl4/P8nLVZ0TSh76aUZ4g7L3FmVts7e5Y6IL7yAwh+hS1XZi0Qag1kGdLRSB+RGq5TQyvv4ru+IDdwQ69H+khHHJqPqMir/D6AGfxSMs41QG7E7WqDmWHf3/hV8HWCtzuKDNnXsEW4XBAtNCsWG/WbVJb3RCKU3zg/Awh653Cy7jF9MJYocx0xQvmXrO1YKO0AlER/0pQKCHSSUBGx2+If/FlvV8qaJDB+dcb95hW2hSyqAxkw98HIb+/Aqb/LgfE5fE282DXrmWxwV8DZsYznTjFsWdfdnSwAI6qDP8l4+b0trHQijILPqwxdX4MjzkhURdrfiFQ==',
      ),
    )
    .set(-2, str2ab.base642buffer('AQAB')),
  JWK: {
    kty: 'RSA',
    alg: 'RS1',
    n: 'zgdFL1k1ceZc-wl4_P8nLVZ0TSh76aUZ4g7L3FmVts7e5Y6IL7yAwh-hS1XZi0Qag1kGdLRSB-RGq5TQyvv4ru-IDdwQ69H-khHHJqPqMir_D6AGfxSMs41QG7E7WqDmWHf3_hV8HWCtzuKDNnXsEW4XBAtNCsWG_WbVJb3RCKU3zg_Awh653Cy7jF9MJYocx0xQvmXrO1YKO0AlER_0pQKCHSSUBGx2-If_FlvV8qaJDB-dcb95hW2hSyqAxkw98HIb-_Aqb_LgfE5fE282DXrmWxwV8DZsYznTjFsWdfdnSwAI6qDP8l4-b0trHQijILPqwxdX4MjzkhURdrfiFQ',
    e: 'AQAB',
  },
  PEM: `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzgdFL1k1ceZc+wl4/P8n
LVZ0TSh76aUZ4g7L3FmVts7e5Y6IL7yAwh+hS1XZi0Qag1kGdLRSB+RGq5TQyvv4
ru+IDdwQ69H+khHHJqPqMir/D6AGfxSMs41QG7E7WqDmWHf3/hV8HWCtzuKDNnXs
EW4XBAtNCsWG/WbVJb3RCKU3zg/Awh653Cy7jF9MJYocx0xQvmXrO1YKO0AlER/0
pQKCHSSUBGx2+If/FlvV8qaJDB+dcb95hW2hSyqAxkw98HIb+/Aqb/LgfE5fE282
DXrmWxwV8DZsYznTjFsWdfdnSwAI6qDP8l4+b0trHQijILPqwxdX4MjzkhURdrfi
FQIDAQAB
-----END PUBLIC KEY-----
`,
  ATTESTATION_OBJECT: str2ab.base64url2buffer(
    'o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZzn__mNzaWdZAQBgVAcleGt8D0UxPBBtXmWKIz9EFYpaGSusT-2mZ-gNKddujUcLy7Hpx4FrYQC9407hcA95s1nTn5J6wHM-3MJkAiZn0lOLfY06B7NXQYwOBo_dKIZHnLUsmroM-YfA8HZAjzh8LVY_HCeqp6OlNuCJ1CHjXVfYYe2mcAXAfjUGLuQjjoSmpu-Mab4cJT1kXn4X8oJsTEKvAhUHcMpywA3m3FHtKRoTlSvUPuzx8x7uYgI5WcwdPRMKpikFW2NM7JoIWtKuYHReivi7E-burnbxc7Zi7sYLsWZi9HcWs2-gHjrvjF_OZeoTNFxqhHCc2HTz1eGdsulgE6AwzJEVeEdXaGF1dGhEYXRhWQFnSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAASKjVmSRjt0nqud40p1PeHgEAIOoSrKEjdRbYsb3qexiOCWZzHIHV0nfWoKlEl9IW3nxdpAEDAzn__iBZAQDOB0UvWTVx5lz7CXj8_yctVnRNKHvppRniDsvcWZW2zt7ljogvvIDCH6FLVdmLRBqDWQZ0tFIH5EarlNDK-_iu74gN3BDr0f6SEccmo-oyKv8PoAZ_FIyzjVAbsTtaoOZYd_f-FXwdYK3O4oM2dewRbhcEC00KxYb9ZtUlvdEIpTfOD8DCHrncLLuMX0wlihzHTFC-Zes7Vgo7QCURH_SlAoIdJJQEbHb4h_8WW9XypokMH51xv3mFbaFLKoDGTD3wchv78Cpv8uB8Tl8TbzYNeuZbHBXwNmxjOdOMWxZ192dLAAjqoM_yXj5vS2sdCKMgs-rDF1fgyPOSFRF2t-IVIUMBAAE',
  ),
};

const RS512 = {
  COSE_MAP: new Map<number, any>()
    .set(1, 3)
    .set(3, -259)
    .set(
      -1,
      str2ab.base642buffer(
        'itaF9xq6JFxqG3GGB+JBGwliT4SVX+e8mM4O3JxOwxKWRF87Q3oC67HNHrhaCJnHW7ATmQmCXDF4JsXxckVjze0hQNMe5vBV8dbky2VlGZVPl6VHh7PiUHm91Nh3z0WbJ95h+8QPiVFWKewQlJqm0i6DDIAk2HDjJ6eD7ItN4MyptgJ6HlwtHNPVU0Y1Obwbut5k89nfRsiOoiW8zedEpNYxbVH1qv3Wd8HTw389ff4MrJUREN21Kq5MWzP7KKQrdVbip+pUM3YhsypBu5veKVV8PtNR/Q0hmeNeGB5qUnYOsO4IUS9eHW8iH7phbrwtJxj/WelFKSwswQ7tpTLlqQ==',
      ),
    )
    .set(-2, str2ab.base642buffer('AQAB')),
  JWK: {
    kty: 'RSA',
    alg: 'RS512',
    n: 'itaF9xq6JFxqG3GGB-JBGwliT4SVX-e8mM4O3JxOwxKWRF87Q3oC67HNHrhaCJnHW7ATmQmCXDF4JsXxckVjze0hQNMe5vBV8dbky2VlGZVPl6VHh7PiUHm91Nh3z0WbJ95h-8QPiVFWKewQlJqm0i6DDIAk2HDjJ6eD7ItN4MyptgJ6HlwtHNPVU0Y1Obwbut5k89nfRsiOoiW8zedEpNYxbVH1qv3Wd8HTw389ff4MrJUREN21Kq5MWzP7KKQrdVbip-pUM3YhsypBu5veKVV8PtNR_Q0hmeNeGB5qUnYOsO4IUS9eHW8iH7phbrwtJxj_WelFKSwswQ7tpTLlqQ',
    e: 'AQAB',
  },
  PEM: `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAitaF9xq6JFxqG3GGB+JB
GwliT4SVX+e8mM4O3JxOwxKWRF87Q3oC67HNHrhaCJnHW7ATmQmCXDF4JsXxckVj
ze0hQNMe5vBV8dbky2VlGZVPl6VHh7PiUHm91Nh3z0WbJ95h+8QPiVFWKewQlJqm
0i6DDIAk2HDjJ6eD7ItN4MyptgJ6HlwtHNPVU0Y1Obwbut5k89nfRsiOoiW8zedE
pNYxbVH1qv3Wd8HTw389ff4MrJUREN21Kq5MWzP7KKQrdVbip+pUM3YhsypBu5ve
KVV8PtNR/Q0hmeNeGB5qUnYOsO4IUS9eHW8iH7phbrwtJxj/WelFKSwswQ7tpTLl
qQIDAQAB
-----END PUBLIC KEY-----
`,
  ATTESTATION_OBJECT: str2ab.base64url2buffer(
    'o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZzkBAmNzaWdZAQB322qZzn7oD5phI5ewlv_ecE3DwKH9WGZMHH5yZlQf57Yq7YCz2KjWGot5Eusu4RuNjRUlcx1WwZrf0SJSVC40PqzXg-pp40pCpYmwFogokMgWSc2zAmOd45Wx-DM-MhKWK87LENpZa6lQ6PZz2WWj9Vb7KBe91ZDU2oRB-3JV6C58Nk6xmZQf1F-HX0ja1RL4dGZV5yobUgoOT808HGsoeyL4sgxmcBTa0z5vU9vQn_7w78NNUX0Xoju9gn6lA_F-aclKTnN8Yt7k5hu1r5mFLxGbK_a7GyIA-eYYxv23RTRykOeG98cH_e5i8ncEgyABs8BRNAfREnOG-WY1gHhlaGF1dGhEYXRhWQFnSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAARR5PzqE2gUjTneucv10vebUAIGXoeLQOlu_--XwziaUPoNKS6RpdGuCW3ZAg_YfNq_KWpAEDAzkBAiBZAQCK1oX3GrokXGobcYYH4kEbCWJPhJVf57yYzg7cnE7DEpZEXztDegLrsc0euFoImcdbsBOZCYJcMXgmxfFyRWPN7SFA0x7m8FXx1uTLZWUZlU-XpUeHs-JQeb3U2HfPRZsn3mH7xA-JUVYp7BCUmqbSLoMMgCTYcOMnp4Psi03gzKm2AnoeXC0c09VTRjU5vBu63mTz2d9GyI6iJbzN50Sk1jFtUfWq_dZ3wdPDfz19_gyslREQ3bUqrkxbM_sopCt1VuKn6lQzdiGzKkG7m94pVXw-01H9DSGZ414YHmpSdg6w7ghRL14dbyIfumFuvC0nGP9Z6UUpLCzBDu2lMuWpIUMBAAE',
  ),
};

const EdDSA = {
  COSE_MAP: new Map<number, any>()
    .set(1, 1)
    .set(3, -8)
    .set(-1, 6)
    .set(-2, str2ab.base642buffer('wUmxVQnXOrjty7SgAbjZaXb1MmYgGQML4cLCW8fqNtk=')),
  JWK: {
    kty: 'OKP',
    alg: 'EdDSA',
    crv: 'Ed25519',
    x: 'wUmxVQnXOrjty7SgAbjZaXb1MmYgGQML4cLCW8fqNtk',
  },
  PEM: `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAwUmxVQnXOrjty7SgAbjZaXb1MmYgGQML4cLCW8fqNtk=
-----END PUBLIC KEY-----
`,
  ATTESTATION_OBJECT: str2ab.base64url2buffer(
    'o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZydjc2lnWEAEdQTpwhfFiIk3Lue0TxTuiZ-5MULNol0OGvCaOjDmUB4bdrRJs93T--xIR2zmjY4g24x_vckd7CHo6SYYzhgOaGF1dGhEYXRhWIFJlg3liA6MaHQ0Fw9kdmBbj-SuuaKGMseZXPO6gx2XY0EAAAA9kd_q15WeRHWtJpsNSCvgiQAgM6m97xU5whIAg9CL79sZnUGRSdzXPHoRlVKGlEzyzeWkAQEDJyAGIVggwUmxVQnXOrjty7SgAbjZaXb1MmYgGQML4cLCW8fqNtk',
  ),
};

const ES256K = {
  COSE_MAP: new Map<number, any>()
    .set(1, 2)
    .set(-1, 8)
    .set(3, -47)
    .set(
      -2,
      Buffer.from([
        0xcb, 0xef, 0xbe, 0x0b, 0x53, 0xf9, 0x88, 0xbc, 0x0c, 0xf6, 0x01, 0xe0, 0xd9, 0x7b, 0x87, 0x8e, 0x82, 0x96,
        0xbe, 0xa2, 0x0c, 0x24, 0x58, 0x92, 0x27, 0xff, 0xe6, 0xba, 0x48, 0xb9, 0x44, 0xdf,
      ]),
    )
    .set(
      -3,
      Buffer.from([
        0xb8, 0x9e, 0x5e, 0xc4, 0x37, 0xea, 0x13, 0x9f, 0x71, 0xf8, 0x55, 0x89, 0xa8, 0xa5, 0xb6, 0xe7, 0x06, 0xf5,
        0xb4, 0xae, 0xa8, 0xc1, 0x44, 0x9d, 0x08, 0xba, 0x56, 0xf8, 0x07, 0xf9, 0x64, 0xdf,
      ]),
    ),
  JWK: {
    kty: 'EC',
    crv: 'secp256k1',
    alg: 'ES256K',
    x: 'y---C1P5iLwM9gHg2XuHjoKWvqIMJFiSJ__muki5RN8',
    y: 'uJ5exDfqE59x-FWJqKW25wb1tK6owUSdCLpW-Af5ZN8',
  },
  PEM: `-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEy+++C1P5iLwM9gHg2XuHjoKWvqIMJFiS
J//muki5RN+4nl7EN+oTn3H4VYmopbbnBvW0rqjBRJ0Iulb4B/lk3w==
-----END PUBLIC KEY-----
`,
  PRIVATE: `-----BEGIN PRIVATE KEY-----
MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgRo2gC67q1qWSZ+nkpHAT
s6PPNqRlwK2+CPBiV93LxkqhRANCAATL774LU/mIvAz2AeDZe4eOgpa+ogwkWJIn
/+a6SLlE37ieXsQ36hOfcfhViailtucG9bSuqMFEnQi6VvgH+WTf
-----END PRIVATE KEY-----
`,
};

const PRIV_KEY = {
  JWK: {
    kty: 'EC',
    alg: 'ES256',
    crv: 'P-256',
    x: 'MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4',
    y: '4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM',
    d: '870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE',
  },
  PEM: `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg870MB6gfuTJ4HtUn
UvYMyJpr5eUZNP4Bk43bVdj3eAGhRANCAAQwoEJM0hwpRIOKLXXJKzfnbqINnwCJ
OjtO7oo8Cq/sPuBLZekkVtmIi1Kzeb371R7oae8fD8ZbZllpW2zOCBcj
-----END PRIVATE KEY-----
`,
};

test('# cose <-> jwk', function (t) {
  t.test('## ES256 cose -> jwk', function (t) {
    try {
      const jwk = KeyParser.cose2jwk(ES256.COSE_MAP);
      t.same(jwk, {
        ...ES256.JWK,
        x: str2ab.buffer2base64url(ES256.JWK.x),
        y: str2ab.buffer2base64url(ES256.JWK.y),
      });
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.test('## ES256K cose -> jwk', function (t) {
    try {
      const jwk = KeyParser.cose2jwk(ES256K.COSE_MAP);
      t.same(jwk, {
        ...ES256K.JWK,
      });
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.test('## PS384 cose -> jwk', function (t) {
    try {
      const jwk = KeyParser.cose2jwk(PS384.COSE_MAP);
      t.same(jwk, {
        ...PS384.JWK,
      });
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.test('## RS1 cose -> jwk', function (t) {
    try {
      const jwk = KeyParser.cose2jwk(RS1.COSE_MAP);
      t.same(jwk, {
        ...RS1.JWK,
      });
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.test('## RS512 cose -> jwk', function (t) {
    try {
      const jwk = KeyParser.cose2jwk(RS512.COSE_MAP);
      t.same(jwk, {
        ...RS512.JWK,
      });
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.test('## EdDSA cose -> jwk', function (t) {
    try {
      const jwk = KeyParser.cose2jwk(EdDSA.COSE_MAP);
      t.same(jwk, {
        ...EdDSA.JWK,
      });
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.test('## ES256 jwk -> cose', function (t) {
    try {
      const cose = KeyParser.jwk2cose({
        ...ES256.JWK,
        x: str2ab.buffer2base64url(ES256.JWK.x),
        y: str2ab.buffer2base64url(ES256.JWK.y),
      });
      t.same(cose, ES256.COSE_MAP);
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.test('## ES256K jwk -> cose', function (t) {
    try {
      const cose = KeyParser.jwk2cose(ES256K.JWK);
      t.same(cose, ES256K.COSE_MAP);
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.test('## PS384 jwk -> cose', function (t) {
    try {
      const cose = KeyParser.jwk2cose(PS384.JWK);
      t.same(cose, PS384.COSE_MAP);
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.test('## RS1 jwk -> cose', function (t) {
    try {
      const cose = KeyParser.jwk2cose(RS1.JWK);
      t.same(cose, RS1.COSE_MAP);
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.test('## RS512 jwk -> cose', function (t) {
    try {
      const cose = KeyParser.jwk2cose(RS512.JWK);
      t.same(cose, RS512.COSE_MAP);
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.test('## EdDSA jwk -> cose', function (t) {
    try {
      const cose = KeyParser.jwk2cose(EdDSA.JWK);
      t.same(cose, EdDSA.COSE_MAP);
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.end();
});

test('# cose <-> pem', function (t) {
  t.test('## ES256 cose -> pem', async function (t) {
    try {
      const pem = await KeyParser.cose2pem(ES256.COSE_MAP);
      t.same(pem.replace(/(\n|\r|\r\n)+/g, '\n'), ES256.PEM.replace(/(\n|\r|\r\n)+/g, '\n'));
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.test('## ES256K cose -> pem', async function (t) {
    try {
      const pem = await KeyParser.cose2pem(ES256K.COSE_MAP);
      t.same(pem.replace(/(\n|\r|\r\n)+/g, '\n'), ES256K.PEM.replace(/(\n|\r|\r\n)+/g, '\n'));
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.test('## PS384 cose -> pem', async function (t) {
    try {
      const pem = await KeyParser.cose2pem(PS384.COSE_MAP);
      t.same(pem.replace(/(\n|\r|\r\n)+/g, '\n'), PS384.PEM.replace(/(\n|\r|\r\n)+/g, '\n'));
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.test('## RS1 cose -> pem', async function (t) {
    try {
      const pem = await KeyParser.cose2pem(RS1.COSE_MAP);
      t.same(pem.replace(/(\n|\r|\r\n)+/g, '\n'), RS1.PEM.replace(/(\n|\r|\r\n)+/g, '\n'));
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.test('## RS512 cose -> pem', async function (t) {
    try {
      const pem = await KeyParser.cose2pem(RS512.COSE_MAP);
      t.same(pem.replace(/(\n|\r|\r\n)+/g, '\n'), RS512.PEM.replace(/(\n|\r|\r\n)+/g, '\n'));
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.test('## EdDSA cose -> pem', async function (t) {
    try {
      const pem = await KeyParser.cose2pem(EdDSA.COSE_MAP);
      t.same(pem.replace(/(\n|\r|\r\n)+/g, '\n'), EdDSA.PEM.replace(/(\n|\r|\r\n)+/g, '\n'));
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.test('## ES256 pem -> cose', async function (t) {
    try {
      const coseMap = await KeyParser.pem2cose(ES256.PEM, 'ES256');
      t.same(coseMap, ES256.COSE_MAP);
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.test('## ES256K pem -> cose', async function (t) {
    try {
      const coseMap = await KeyParser.pem2cose(ES256K.PEM, 'ES256K');
      t.same(coseMap, ES256K.COSE_MAP);
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.test('## PS384 pem -> cose', async function (t) {
    try {
      const coseMap = await KeyParser.pem2cose(PS384.PEM, 'PS384');
      t.same(coseMap, PS384.COSE_MAP);
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.test('## RS1 pem -> cose', async function (t) {
    try {
      const coseMap = await KeyParser.pem2cose(RS1.PEM, 'RS1');
      t.same(coseMap, RS1.COSE_MAP);
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.test('## RS512 pem -> cose', async function (t) {
    try {
      const coseMap = await KeyParser.pem2cose(RS512.PEM, 'RS512');
      t.same(coseMap, RS512.COSE_MAP);
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.test('## EdDSA pem -> cose', async function (t) {
    try {
      const coseMap = await KeyParser.pem2cose(EdDSA.PEM, 'EdDSA');
      t.same(coseMap, EdDSA.COSE_MAP);
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.end();
});

test('# jwk <-> pem', function (t) {
  t.test('## ES256 jwk -> pem', async function (t) {
    try {
      const pem = await KeyParser.jwk2pem({
        ...ES256.JWK,
        x: str2ab.buffer2base64url(ES256.JWK.x),
        y: str2ab.buffer2base64url(ES256.JWK.y),
      });
      t.same(pem.replace(/(\n|\r|\r\n)+/g, '\n'), ES256.PEM.replace(/(\n|\r|\r\n)+/g, '\n'));
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.test('## ES256K jwk -> pem', async function (t) {
    try {
      const pem = await KeyParser.jwk2pem(ES256K.JWK);
      t.same(pem.replace(/(\n|\r|\r\n)+/g, '\n'), ES256K.PEM.replace(/(\n|\r|\r\n)+/g, '\n'));
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.test('## PS384 jwk -> pem', async function (t) {
    try {
      const pem = await KeyParser.jwk2pem(PS384.JWK);
      t.same(pem.replace(/(\n|\r|\r\n)+/g, '\n'), PS384.PEM.replace(/(\n|\r|\r\n)+/g, '\n'));
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.test('## RS1 jwk -> pem', async function (t) {
    try {
      const pem = await KeyParser.jwk2pem(RS1.JWK);
      t.same(pem.replace(/(\n|\r|\r\n)+/g, '\n'), RS1.PEM.replace(/(\n|\r|\r\n)+/g, '\n'));
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.test('## RS512 jwk -> pem', async function (t) {
    try {
      const pem = await KeyParser.jwk2pem(RS512.JWK);
      t.same(pem.replace(/(\n|\r|\r\n)+/g, '\n'), RS512.PEM.replace(/(\n|\r|\r\n)+/g, '\n'));
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.test('## EdDSA jwk -> pem', async function (t) {
    try {
      const pem = await KeyParser.jwk2pem(EdDSA.JWK);
      t.same(pem.replace(/(\n|\r|\r\n)+/g, '\n'), EdDSA.PEM.replace(/(\n|\r|\r\n)+/g, '\n'));
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.test('## PrivateKey jwk -> pem', async function (t) {
    try {
      const pem = await KeyParser.jwk2pem(PRIV_KEY.JWK);
      t.same(pem.replace(/(\n|\r|\r\n)+/g, '\n'), PRIV_KEY.PEM.replace(/(\n|\r|\r\n)+/g, '\n'));
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.test('## ES256 pem -> jwk', async function (t) {
    try {
      const jwk = await KeyParser.pem2jwk(ES256.PEM);

      const expected = {
        kty: ES256.JWK.kty,
        crv: ES256.JWK.crv,
        x: str2ab.buffer2base64url(ES256.JWK.x),
        y: str2ab.buffer2base64url(ES256.JWK.y),
      };
      t.same(jwk, expected);
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.test('## ES256K pem -> jwk', async function (t) {
    try {
      const jwk = await KeyParser.pem2jwk(ES256K.PEM);

      const expected = {
        kty: ES256K.JWK.kty,
        crv: ES256K.JWK.crv,
        x: ES256K.JWK.x,
        y: ES256K.JWK.y,
      };
      t.same(jwk, expected);
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.test('## PS384 pem -> jwk', async function (t) {
    try {
      const jwk = await KeyParser.pem2jwk(PS384.PEM);

      const expected = {
        kty: PS384.JWK.kty,
        n: PS384.JWK.n,
        e: PS384.JWK.e,
      };
      t.same(jwk, expected);
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.test('## RS1 pem -> jwk', async function (t) {
    try {
      const jwk = await KeyParser.pem2jwk(RS1.PEM);

      const expected = {
        kty: RS1.JWK.kty,
        n: RS1.JWK.n,
        e: RS1.JWK.e,
      };
      t.same(jwk, expected);
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.test('## RS512 pem -> jwk', async function (t) {
    try {
      const jwk = await KeyParser.pem2jwk(RS512.PEM);

      const expected = {
        kty: RS512.JWK.kty,
        n: RS512.JWK.n,
        e: RS512.JWK.e,
      };
      t.same(jwk, expected);
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.test('## EdDSA pem -> jwk', async function (t) {
    try {
      const jwk = await KeyParser.pem2jwk(EdDSA.PEM);

      const expected = {
        kty: EdDSA.JWK.kty,
        crv: EdDSA.JWK.crv,
        x: EdDSA.JWK.x,
      };
      t.same(jwk, expected);
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.test('## PrivateKey pem -> jwk', async function (t) {
    try {
      const jwk = await KeyParser.pem2jwk(PRIV_KEY.PEM);

      const expected = {
        kty: PRIV_KEY.JWK.kty,
        crv: PRIV_KEY.JWK.crv,
        x: PRIV_KEY.JWK.x,
        y: PRIV_KEY.JWK.y,
        d: PRIV_KEY.JWK.d,
      };
      t.same(jwk, expected);
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.end();
});

test('# attestationObject -> jwk', function (t) {
  t.test('## ES256 attestationObject -> jwk', function (t) {
    try {
      const jwk = KeyParser.attestationObject2jwk(ES256.ATTESTATION_OBJECT);
      t.same(jwk, {
        ...ES256.JWK,
        x: str2ab.buffer2base64url(ES256.JWK.x),
        y: str2ab.buffer2base64url(ES256.JWK.y),
      });
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.test('## PS384 attestationObject -> jwk', function (t) {
    try {
      const jwk = KeyParser.attestationObject2jwk(PS384.ATTESTATION_OBJECT);
      t.same(jwk, {
        ...PS384.JWK,
      });
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.test('## RS1 attestationObject -> jwk', function (t) {
    try {
      const jwk = KeyParser.attestationObject2jwk(RS1.ATTESTATION_OBJECT);
      t.same(jwk, {
        ...RS1.JWK,
      });
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.test('## RS512 attestationObject -> jwk', function (t) {
    try {
      const jwk = KeyParser.attestationObject2jwk(RS512.ATTESTATION_OBJECT);
      t.same(jwk, {
        ...RS512.JWK,
      });
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.test('## EdDSA attestationObject -> jwk', function (t) {
    try {
      const jwk = KeyParser.attestationObject2jwk(EdDSA.ATTESTATION_OBJECT);
      t.same(jwk, {
        ...EdDSA.JWK,
      });
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.end();
});

test('# der <-> pem', function (t) {
  t.test('## publickey pem -> der', async function (t) {
    try {
      const keys = crypto.generateKeyPairSync('rsa', {
        modulusLength: 4096,
        publicKeyEncoding: {
          type: 'spki',
          format: 'pem',
        },
        privateKeyEncoding: {
          type: 'pkcs1',
          format: 'pem',
        },
      });
      const expected = crypto.createPublicKey(keys.publicKey).export({
        type: 'spki',
        format: 'der',
      });

      const der = KeyParser.pem2der(keys.publicKey);
      t.same(der, expected);
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.test('## privatekey pem -> der', async function (t) {
    try {
      const keys = crypto.generateKeyPairSync('rsa', {
        modulusLength: 4096,
        publicKeyEncoding: {
          type: 'spki',
          format: 'pem',
        },
        privateKeyEncoding: {
          type: 'pkcs1',
          format: 'pem',
        },
      });
      const expected = crypto.createPrivateKey(keys.privateKey).export({
        type: 'pkcs1',
        format: 'der',
      });

      const der = KeyParser.pem2der(keys.privateKey);
      t.same(der, expected);
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.test('## publickey der -> pem', async function (t) {
    try {
      const keys = crypto.generateKeyPairSync('rsa', {
        modulusLength: 4096,
        publicKeyEncoding: {
          type: 'spki',
          format: 'der',
        },
        privateKeyEncoding: {
          type: 'pkcs1',
          format: 'der',
        },
      });
      const expected = crypto
        .createPublicKey({
          key: keys.publicKey,
          format: 'der',
          type: 'spki',
        })
        .export({
          type: 'spki',
          format: 'pem',
        }) as string;

      const pem = KeyParser.der2pem('PUBLIC KEY', keys.publicKey);
      t.same(pem.replace(/(\n|\r|\r\n)+/g, '\n'), expected.replace(/(\n|\r|\r\n)+/g, '\n'));
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.test('## privatekey der -> pem', async function (t) {
    try {
      const keys = crypto.generateKeyPairSync('rsa', {
        modulusLength: 4096,
        publicKeyEncoding: {
          type: 'spki',
          format: 'der',
        },
        privateKeyEncoding: {
          type: 'pkcs1',
          format: 'der',
        },
      });
      const expected = crypto
        .createPrivateKey({
          key: keys.privateKey,
          format: 'der',
          type: 'pkcs1',
        })
        .export({
          type: 'pkcs1',
          format: 'pem',
        }) as string;

      const pem = KeyParser.der2pem('PRIVATE KEY', keys.privateKey);
      t.same(pem.replace(/(\n|\r|\r\n)+/g, '\n'), expected.replace(/(\n|\r|\r\n)+/g, '\n').replace(/(RSA )/g, ''));
      t.end();
    } catch (err) {
      let message = `${t.name}: error`;
      if (err != null && err instanceof Error) {
        message = err.message;
      }
      t.fail(message);
    }
  });

  t.end();
});
