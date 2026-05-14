# Changelog

## [0.9.2](https://github.com/smithery-ai/agent.pw/compare/agent.pw-v0.9.1...agent.pw-v0.9.2) (2026-05-14)


### Bug Fixes

* strip OIDC scopes from PRM discovery ([#170](https://github.com/smithery-ai/agent.pw/issues/170)) ([533de66](https://github.com/smithery-ai/agent.pw/commit/533de66a319bdd7cf2e5e84f09bf5c0c1e8a8a2c))

## [0.9.1](https://github.com/smithery-ai/agent.pw/compare/agent.pw-v0.9.0...agent.pw-v0.9.1) (2026-05-14)


### Bug Fixes

* **oauth:** align dynamic client auth with server metadata ([#166](https://github.com/smithery-ai/agent.pw/issues/166)) ([39f0942](https://github.com/smithery-ai/agent.pw/commit/39f094258c4e4547268659aee7d67ad6e64205b2))
* **oauth:** fall back to PRM scopes when challenge omits scope ([#169](https://github.com/smithery-ai/agent.pw/issues/169)) ([309bc25](https://github.com/smithery-ai/agent.pw/commit/309bc254abeb288897f073d62ef870b2c0488a61))

## [0.9.0](https://github.com/smithery-ai/agent.pw/compare/agent.pw-v0.8.2...agent.pw-v0.9.0) (2026-04-30)


### Features

* support ID-JAG challenge exchange ([#164](https://github.com/smithery-ai/agent.pw/issues/164)) ([1af73fb](https://github.com/smithery-ai/agent.pw/commit/1af73fb168dd41df6b9ba64108051b339087e527))

## [0.8.2](https://github.com/smithery-ai/agent.pw/compare/agent.pw-v0.8.1...agent.pw-v0.8.2) (2026-04-18)


### Bug Fixes

* fall back to auth-server metadata when PRM malformed ([#162](https://github.com/smithery-ai/agent.pw/issues/162)) ([45c5aba](https://github.com/smithery-ai/agent.pw/commit/45c5abab142a08b6dceeb31ab0c27f5b575ef1b1))

## [0.8.1](https://github.com/smithery-ai/agent.pw/compare/agent.pw-v0.8.0...agent.pw-v0.8.1) (2026-04-13)


### Bug Fixes

* remove diagnostic logging from refresh path ([#160](https://github.com/smithery-ai/agent.pw/issues/160)) ([f62f027](https://github.com/smithery-ai/agent.pw/commit/f62f027db4fdd53e8920d57d35beee0282c86d60))

## [0.8.0](https://github.com/smithery-ai/agent.pw/compare/agent.pw-v0.7.0...agent.pw-v0.8.0) (2026-04-12)


### Features

* allow profile-only init without encryption key ([#156](https://github.com/smithery-ai/agent.pw/issues/156)) ([14456bb](https://github.com/smithery-ai/agent.pw/commit/14456bb69aecc2a33dd2eedc151bcf9d512cbbe2))


### Bug Fixes

* instrument refresh credential delete path ([#159](https://github.com/smithery-ai/agent.pw/issues/159)) ([36852f7](https://github.com/smithery-ai/agent.pw/commit/36852f7318c57c4aca92481415c64940b6b6493b))

## [0.7.0](https://github.com/smithery-ai/agent.pw/compare/agent.pw-v0.6.2...agent.pw-v0.7.0) (2026-04-12)


### Features

* **SMI-1688:** model profiles as HTTP inputs plus OAuth ([#153](https://github.com/smithery-ai/agent.pw/issues/153)) ([28b7394](https://github.com/smithery-ai/agent.pw/commit/28b73944095266ec7af7794b89c31e64f81be3fb))


### Bug Fixes

* clear stale credential on refresh token rejection ([#155](https://github.com/smithery-ai/agent.pw/issues/155)) ([c2aa4d7](https://github.com/smithery-ai/agent.pw/commit/c2aa4d789c9ac41aaefb9508084750c0fe25d5b1))

## [0.6.2](https://github.com/smithery-ai/agent.pw/compare/agent.pw-v0.6.1...agent.pw-v0.6.2) (2026-04-10)


### Bug Fixes

* fall back on non-JSON metadata ([#151](https://github.com/smithery-ai/agent.pw/issues/151)) ([9dafb03](https://github.com/smithery-ai/agent.pw/commit/9dafb03e7757ab1dc596e46b6e8ba0bcff333791))

## [0.6.1](https://github.com/smithery-ai/agent.pw/compare/agent.pw-v0.6.0...agent.pw-v0.6.1) (2026-04-10)


### Bug Fixes

* RFC 9728bis resource prefix matching ([#149](https://github.com/smithery-ai/agent.pw/issues/149)) ([fea8f30](https://github.com/smithery-ai/agent.pw/commit/fea8f300f52af282c98d8390cd3e4e331d18228c))

## [0.6.0](https://github.com/smithery-ai/agent.pw/compare/agent.pw-v0.5.6...agent.pw-v0.6.0) (2026-04-02)


### Features

* add env credentials to the vault ([#104](https://github.com/smithery-ai/agent.pw/issues/104)) ([1bd1bbc](https://github.com/smithery-ai/agent.pw/commit/1bd1bbc64072623f1cdb31ccf907e59680edf9ba))
* add high-level connect flow APIs ([#107](https://github.com/smithery-ai/agent.pw/issues/107)) ([94fc529](https://github.com/smithery-ai/agent.pw/commit/94fc529995d4d5838b4799dd347fca2b8822186a))
* add local HTTP proxy and CONNECT tunneling ([#88](https://github.com/smithery-ai/agent.pw/issues/88)) ([9674d23](https://github.com/smithery-ai/agent.pw/commit/9674d237f9fe1a8d963838345e78246b0d084b1a))
* add verification table and fix drizzle-kit scripts ([#89](https://github.com/smithery-ai/agent.pw/issues/89)) ([7a2f949](https://github.com/smithery-ai/agent.pw/commit/7a2f949a539927abff572aa211e5dfda47d55631))
* export first-class error types and guards ([#122](https://github.com/smithery-ai/agent.pw/issues/122)) ([454660d](https://github.com/smithery-ai/agent.pw/commit/454660d5a01809ed8e9c8ed90fab5885642b6d18))
* keep local bootstrap internal to onboarding ([#94](https://github.com/smithery-ai/agent.pw/issues/94)) ([23f5710](https://github.com/smithery-ai/agent.pw/commit/23f5710eb913608ad22fd776cb17d2976885b24c))
* make init launch the bundled daemon ([#86](https://github.com/smithery-ai/agent.pw/issues/86)) ([4c9daff](https://github.com/smithery-ai/agent.pw/commit/4c9daffa4ad745d70bb8cf578e34cbf1ec042a0d))
* rebuild agent.pw as a framework package ([#102](https://github.com/smithery-ai/agent.pw/issues/102)) ([59d17d5](https://github.com/smithery-ai/agent.pw/commit/59d17d5b9d812310e8dbd3abf692b694f80e0faf))
* support pushing provided CLI tokens ([#97](https://github.com/smithery-ai/agent.pw/issues/97)) ([e1de4a7](https://github.com/smithery-ai/agent.pw/commit/e1de4a70926a03c19508b4a68fb264f5d0903e61))
* track issued biscuit tokens ([#99](https://github.com/smithery-ai/agent.pw/issues/99)) ([c6afa65](https://github.com/smithery-ai/agent.pw/commit/c6afa653c49821107d923cd0c78b4baef780656d))
* use real ltree-backed dot paths ([#113](https://github.com/smithery-ai/agent.pw/issues/113)) ([ffed4a0](https://github.com/smithery-ai/agent.pw/commit/ffed4a0605ed35276a1fa595df105dc1e4764929))


### Bug Fixes

* accept broader Drizzle DB clients ([#128](https://github.com/smithery-ai/agent.pw/issues/128)) ([47a8a5e](https://github.com/smithery-ai/agent.pw/commit/47a8a5e14b26446f26b25e1ac5efb3cb33a5c1d5))
* allow hosted shells to reach local instances ([#85](https://github.com/smithery-ai/agent.pw/issues/85)) ([305b78d](https://github.com/smithery-ai/agent.pw/commit/305b78d892ecdc8c9c60e835e917e33fa4c632fa))
* challenged OAuth discovery handling ([#137](https://github.com/smithery-ai/agent.pw/issues/137)) ([b2a5e00](https://github.com/smithery-ai/agent.pw/commit/b2a5e00f7ba5287cbc9e17ca00199c26c6d6f23a))
* filter openid from requested scopes ([#141](https://github.com/smithery-ai/agent.pw/issues/141)) ([01e2769](https://github.com/smithery-ai/agent.pw/commit/01e2769ae3cf7f829605019e32928a85941ff77d))
* follow MCP auth server discovery order ([#106](https://github.com/smithery-ai/agent.pw/issues/106)) ([fa61499](https://github.com/smithery-ai/agent.pw/commit/fa61499bb313c497c673c008c44a9f996a7b70c6))
* ignore generated changelog formatting ([#110](https://github.com/smithery-ai/agent.pw/issues/110)) ([a08ba0e](https://github.com/smithery-ai/agent.pw/commit/a08ba0e9f3ca5207311cd4d7f3b53dd15c9e9da1))
* make agent.pw server exports consumable ([#84](https://github.com/smithery-ai/agent.pw/issues/84)) ([0d1e3b6](https://github.com/smithery-ai/agent.pw/commit/0d1e3b641847150e008516d44fcf383544fdbf25))
* preserve extra credential headers on OAuth token refresh ([#95](https://github.com/smithery-ai/agent.pw/issues/95)) ([1a8af96](https://github.com/smithery-ai/agent.pw/commit/1a8af967967e65a4ddabe821137ff900da71bec1))
* respect OAuth resource paths ([#126](https://github.com/smithery-ai/agent.pw/issues/126)) ([cbeba95](https://github.com/smithery-ai/agent.pw/commit/cbeba95626071bdf7fa47776fb82e712928e0a09))
* restore cloud compatibility for OSS server ([#92](https://github.com/smithery-ai/agent.pw/issues/92)) ([eb84797](https://github.com/smithery-ai/agent.pw/commit/eb8479729713c3a9427f656584eee2905a4102f2))
* restore release version baseline ([41b1dde](https://github.com/smithery-ai/agent.pw/commit/41b1dde2894b92502c682cc4901a442a1b366545))
* simplify docs and document option ordering ([#130](https://github.com/smithery-ai/agent.pw/issues/130)) ([882bbc7](https://github.com/smithery-ai/agent.pw/commit/882bbc76425e2c0879ee3946c723c1243cc8f069))
* strip id_token from token responses before validation ([#142](https://github.com/smithery-ai/agent.pw/issues/142)) ([15ff929](https://github.com/smithery-ai/agent.pw/commit/15ff929221232b194b0dc91057c0ec5097a6618e))
* surface actionable error for id_token issuer mismatch ([#139](https://github.com/smithery-ai/agent.pw/issues/139)) ([47cffac](https://github.com/smithery-ai/agent.pw/commit/47cffac5fad9aaa76302f4d90895ad63f3b7dafe))
* surface root-cause detail in OAuth errors (SMI-1730) ([#147](https://github.com/smithery-ai/agent.pw/issues/147)) ([2db0501](https://github.com/smithery-ai/agent.pw/commit/2db05018419ce8a05d0a6ec795c4f0ae4e33afe8))


### Reverts

* remove openid filter and id_token strip ([#144](https://github.com/smithery-ai/agent.pw/issues/144)) ([35df09f](https://github.com/smithery-ai/agent.pw/commit/35df09f9904c8c4626d11f34f72934645ff62bb9))

## [0.5.6](https://github.com/smithery-ai/agent.pw/compare/agent.pw-v0.5.5...agent.pw-v0.5.6) (2026-04-01)


### Reverts

* remove openid filter and id_token strip ([#144](https://github.com/smithery-ai/agent.pw/issues/144)) ([35df09f](https://github.com/smithery-ai/agent.pw/commit/35df09f9904c8c4626d11f34f72934645ff62bb9))

## [0.5.5](https://github.com/smithery-ai/agent.pw/compare/agent.pw-v0.5.4...agent.pw-v0.5.5) (2026-04-01)


### Bug Fixes

* strip id_token from token responses before validation ([#142](https://github.com/smithery-ai/agent.pw/issues/142)) ([15ff929](https://github.com/smithery-ai/agent.pw/commit/15ff929221232b194b0dc91057c0ec5097a6618e))

## [0.5.4](https://github.com/smithery-ai/agent.pw/compare/agent.pw-v0.5.3...agent.pw-v0.5.4) (2026-04-01)


### Bug Fixes

* filter openid from requested scopes ([#141](https://github.com/smithery-ai/agent.pw/issues/141)) ([01e2769](https://github.com/smithery-ai/agent.pw/commit/01e2769ae3cf7f829605019e32928a85941ff77d))
* surface actionable error for id_token issuer mismatch ([#139](https://github.com/smithery-ai/agent.pw/issues/139)) ([47cffac](https://github.com/smithery-ai/agent.pw/commit/47cffac5fad9aaa76302f4d90895ad63f3b7dafe))

## [0.5.3](https://github.com/smithery-ai/agent.pw/compare/agent.pw-v0.5.2...agent.pw-v0.5.3) (2026-03-31)


### Bug Fixes

* challenged OAuth discovery handling ([#137](https://github.com/smithery-ai/agent.pw/issues/137)) ([b2a5e00](https://github.com/smithery-ai/agent.pw/commit/b2a5e00f7ba5287cbc9e17ca00199c26c6d6f23a))

## [0.5.2](https://github.com/smithery-ai/agent.pw/compare/agent.pw-v0.5.1...agent.pw-v0.5.2) (2026-03-30)


### Bug Fixes

* accept broader Drizzle DB clients ([#128](https://github.com/smithery-ai/agent.pw/issues/128)) ([47a8a5e](https://github.com/smithery-ai/agent.pw/commit/47a8a5e14b26446f26b25e1ac5efb3cb33a5c1d5))
* simplify docs and document option ordering ([#130](https://github.com/smithery-ai/agent.pw/issues/130)) ([882bbc7](https://github.com/smithery-ai/agent.pw/commit/882bbc76425e2c0879ee3946c723c1243cc8f069))

## [0.5.1](https://github.com/smithery-ai/agent.pw/compare/agent.pw-v0.5.0...agent.pw-v0.5.1) (2026-03-30)


### Bug Fixes

* respect OAuth resource paths ([#126](https://github.com/smithery-ai/agent.pw/issues/126)) ([cbeba95](https://github.com/smithery-ai/agent.pw/commit/cbeba95626071bdf7fa47776fb82e712928e0a09))

## [0.5.0](https://github.com/smithery-ai/agent.pw/compare/agent.pw-v0.4.0...agent.pw-v0.5.0) (2026-03-29)


### Features

* add env credentials to the vault ([#104](https://github.com/smithery-ai/agent.pw/issues/104)) ([1bd1bbc](https://github.com/smithery-ai/agent.pw/commit/1bd1bbc64072623f1cdb31ccf907e59680edf9ba))
* add high-level connect flow APIs ([#107](https://github.com/smithery-ai/agent.pw/issues/107)) ([94fc529](https://github.com/smithery-ai/agent.pw/commit/94fc529995d4d5838b4799dd347fca2b8822186a))
* export first-class error types and guards ([#122](https://github.com/smithery-ai/agent.pw/issues/122)) ([454660d](https://github.com/smithery-ai/agent.pw/commit/454660d5a01809ed8e9c8ed90fab5885642b6d18))
* rebuild agent.pw as a framework package ([#102](https://github.com/smithery-ai/agent.pw/issues/102)) ([59d17d5](https://github.com/smithery-ai/agent.pw/commit/59d17d5b9d812310e8dbd3abf692b694f80e0faf))
* use real ltree-backed dot paths ([#113](https://github.com/smithery-ai/agent.pw/issues/113)) ([ffed4a0](https://github.com/smithery-ai/agent.pw/commit/ffed4a0605ed35276a1fa595df105dc1e4764929))


### Bug Fixes

* follow MCP auth server discovery order ([#106](https://github.com/smithery-ai/agent.pw/issues/106)) ([fa61499](https://github.com/smithery-ai/agent.pw/commit/fa61499bb313c497c673c008c44a9f996a7b70c6))
* ignore generated changelog formatting ([#110](https://github.com/smithery-ai/agent.pw/issues/110)) ([a08ba0e](https://github.com/smithery-ai/agent.pw/commit/a08ba0e9f3ca5207311cd4d7f3b53dd15c9e9da1))
* restore release version baseline ([41b1dde](https://github.com/smithery-ai/agent.pw/commit/41b1dde2894b92502c682cc4901a442a1b366545))
