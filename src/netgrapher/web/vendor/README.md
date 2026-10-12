# Vendored frontend libraries

Pinned third-party browser builds, served locally. Nothing is loaded from a CDN (design NFR-8).
Each tarball was downloaded from registry.npmjs.org and checked against the registry's sha512
integrity value before extraction. Every library is MIT-licensed; its LICENSE file sits next to it.

| Library | Version | File | SHA-256 |
|---|---|---|---|
| cytoscape | 3.30.2 | `cytoscape/cytoscape.min.js` | `83e8c54a6bec655bfd81df07df605649c268af69aeca67a5ea2da54ea42dac81` |
| layout-base | 2.0.1 | `layout-base/layout-base.js` | `ec15ab5df9af3f20708f4faab994accf91cda71848cd5bb10a23432cc50b6745` |
| cose-base | 2.2.0 | `cose-base/cose-base.js` | `7cae9509bd36235a63a85e71c8d9fa2cd0bc1d0c1ecc5b5a737976f39d040ddf` |
| cytoscape-fcose | 2.2.0 | `cytoscape-fcose/cytoscape-fcose.js` | `4b1cab218d74996aa59cd8473f9239cc6398b8c1774d84d7e59ad9a68959cb57` |
| dagre (bundles graphlib 2.1.8, lodash 4.17.x) | 0.8.5 | `dagre/dagre.min.js` | `62eb9787ccfdbdf4148d4d99d31dbf9ee4770eafee81e637d759b52aac22cd51` |
| cytoscape-dagre | 2.5.0 | `cytoscape-dagre/cytoscape-dagre.js` | `bf70fe402991dcbff33e05a7e4a5271c78020bb75e85d1c80ab7538e4157112e` |

Not used: `cytoscape-svg` (GPL-3.0, incompatible with NFR-10; netgrapher has its own SVG
exporter in `js/svg.js`) and `elkjs` (EPL-2.0; dagre covers the hierarchical layout).

`tests/unit/test_server.py` verifies these hashes.
