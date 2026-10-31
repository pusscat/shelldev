"""The library catalog served to the editor's library page.

Every entry is generated from external tooling and vendored or generated here;
there are no hand-written entries anymore:

  - ``pwn_catalog``  — pwntools shellcraft payloads and encoder stubs, generated
                       at runtime (loaded as raw bytes).
  - ``msf_catalog``  — Metasploit Framework payloads and encoder decoder-stubs,
                       vendored as bytes offline (payloads load as editable
                       assembly when faithful, otherwise as raw bytes).

Each entry carries metadata for the library page's search and sort: arch, os,
category (functionality), kind (payload or decoder) and source.
"""


def catalog() -> list[dict]:
    """The full library for the API: pwntools-generated entries plus the
    vendored Metasploit entries."""
    from . import msf_catalog, pwn_catalog

    out: list[dict] = []
    out.extend(pwn_catalog.entries())
    out.extend(msf_catalog.entries())
    return out
